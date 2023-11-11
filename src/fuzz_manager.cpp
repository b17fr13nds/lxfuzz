#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <signal.h>
#include <mqueue.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "fuzz_manager.h"

std::vector<instance_t*> instances;

auto print_usage_and_exit(char **argv) -> void {
  std::cout << argv[0] << ": <instances> <fuzzer options...>" << std::endl;
  exit(0);
}

auto number_of_files_in_directory(std::filesystem::path path) -> std::size_t {
  using std::filesystem::directory_iterator;
  return std::distance(directory_iterator(path), directory_iterator{});
}

auto parse_cmdline(int32_t instance_no) -> const char ** {
  std::ifstream f;
  std::string tmp;
  std::vector<std::string> *v = new std::vector<std::string>;

  f.open("./cmdline.cfg");

  while(!f.eof()) {
    getline(f, tmp, '|');
    v->push_back(tmp);
  }

  v->push_back("-fi");
  v->push_back(std::to_string(instance_no));

  const char **args{new const char *[v->size()+1]};
  int32_t cnt{0};

  for(auto &elem : *v) {
    args[cnt++] = elem.c_str();
  }

  args[cnt] = NULL;
  f.close();

  return args;
}

auto prepare_instance(int32_t instance_no) -> void {
  int32_t pid{}, input_pipefd[2], output_pipefd[2];

  const char **args = parse_cmdline(instance_no);

  if(pipe(input_pipefd) == -1) error("pipe");
  if(pipe(output_pipefd) == -1) error("pipe");

  switch(pid = fork()) {
    case -1:
    exit(-1);
    case 0:
    dup2(input_pipefd[0], 0);
    dup2(output_pipefd[1], 1);
    dup2(output_pipefd[1], 2);

    close(input_pipefd[1]);
    close(output_pipefd[0]);

    execve(args[0], const_cast<char * const *>(args), NULL);
    exit(0);
    default:
    instances.at(instance_no)->pid = pid;

    close(input_pipefd[0]);
    close(output_pipefd[1]);

    char c{};
    do {
      if(read(output_pipefd[0], &c, 1) == -1) error("read");
    } while(c != '$');

    instances.at(instance_no)->fd = input_pipefd[1];
    close(output_pipefd[0]);
  }

  return;
}

auto start_instance(int32_t instance_no, std::string fuzzer_args) -> void {
  std::string cmd{"./fuzzer " + fuzzer_args + "\n\r"};

  if(write(instances.at(instance_no)->fd, cmd.c_str(), cmd.size()) == -1) error("write");

  return;
}

auto stop_instance(int32_t instance_no) -> void {
  if(!instances.at(instance_no)->pid) return;

  if(kill(instances.at(instance_no)->pid, SIGKILL) == -1) error("kill");
  if(waitpid(instances.at(instance_no)->pid, NULL, 0) == -1) error("waitpid");

  instances.at(instance_no)->pid = 0;

  return;
}

auto check_if_alive(int32_t idx) -> bool {
  if(!waitpid(instances.at(idx)->pid, NULL, WNOHANG)) return true;
  return false;
}

auto check_if_log_activity(int32_t idx) -> bool {
  size_t filesz;

  for(size_t i{0}; i < number_of_files_in_directory("./kernel/data/instance" + std::to_string(idx)); i++) {
    filesz = std::filesystem::file_size("./kernel/data/instance" + std::to_string(idx) + "/log_t" + std::to_string(i));

    if(filesz == instances.at(idx)->logsizes[i]) {
      return false;
    }

    instances.at(idx)->logsizes[i] = filesz;
  }
  return true;
}

auto save_crash(int32_t instance_no) -> void {
  std::filesystem::copy("./kernel/data/instance" + std::to_string(instance_no), "./kernel/data/instance" + std::to_string(instance_no) + "_crash" + std::to_string(instances.at(instance_no)->crashes)); 
}

auto cleanup(int32_t x) -> void {
  if(mq_unlink("/fuzzer") == -1) perror("mq_unlink");

  for(uint64_t i{0}; i < instances.size(); i++)
    stop_instance(i);

  exit(0);
}

auto parse_fuzzer_args(char **start) -> std::string {
  std::string ret{};

  for(int i{0}; start[i] != NULL; i++) {
    ret += start[i];
    ret += " ";
  }

  return ret;
}

auto main(int32_t argc, char **argv) -> int32_t {
  struct mq_attr attr{0x0,0x1,sizeof(stats_t),0x0};
  auto crashes{0}, ninstances{std::stoi(argv[1])};
  std::string fuzzer_args{};
  mqd_t desc{0};

  std::cout << "welcome to lxfuzz v0.0.1" << std::endl;

  if(argc < 2) print_usage_and_exit(argv);
  fuzzer_args = parse_fuzzer_args(&argv[2]);

  signal(SIGINT, cleanup);

  desc = mq_open("/fuzzer", O_RDONLY|O_CREAT|O_NONBLOCK, S_IRWXU|S_IRWXG|S_IRWXO, &attr);
  if(desc == -1) error("mq_open");

  std::cout << "starting instance" << std::endl;

  for(auto i{0}; i < ninstances; i++) {
    std::filesystem::create_directory("./kernel/data/instance" + std::to_string(i));
    instances.push_back(new instance_t);
    prepare_instance(i);
    instances.back()->crashes = 0;
    instances.back()->logsizes = new uint64_t[number_of_files_in_directory("./kernel/data/instance" + std::to_string(i))];

    for(size_t j{0}; j < number_of_files_in_directory("./kernel/data/instance" + std::to_string(i)); j++)
      instances.back()->logsizes[j] = 0;
  }

  for(auto i{0}; i < ninstances; i++)
    start_instance(i, fuzzer_args);

  std::cout << "instance started; fuzzer ready" << std::endl;
  stats_t tmp{0}, tot{0};

  while(1) {
    tot.execs_per_sec = 0;

    for(auto i{0}; i < ninstances; i++) {
retry:

      if(!check_if_alive(i)) {
        std::cout << "instance " << i << " crashed!" << std::endl;

        save_crash(i);

        for (const auto& e : std::filesystem::directory_iterator("./kernel/data/instance" + std::to_string(i)))
          std::filesystem::remove_all(e.path());

        prepare_instance(i);
        start_instance(i, fuzzer_args);

        crashes++;
        instances.at(i)->crashes++;

        std::cout << "instance " << i << " brought back up!" << std::endl;
      } else {
        if(mq_receive(desc, (char *)&tmp, sizeof(stats_t), 0) == -1) goto retry;

        tot.total_execs += tmp.total_execs;
        tot.execs_per_sec += tmp.execs_per_sec;
      }

      if(!check_if_log_activity(i)) {
        std::cout << "instance " << i << " hangs!" << std::endl;

        stop_instance(i);

	      for(size_t j{0}; j < number_of_files_in_directory("./kernel/data/instance" + std::to_string(i)); j++)
          instances.at(i)->logsizes[j] = 0;

        prepare_instance(i);
        start_instance(i, fuzzer_args);

        std::cout << "instance " << i << " brought back up!" << std::endl;
      }
    }

    tot.execs_per_sec /= ninstances;

    std::cout << "total execs: " << tot.total_execs << std::endl;
    std::cout << "execs per second: " << tot.execs_per_sec << std::endl;
    std::cout << "crashes: " << crashes << std::endl;
  }

  if(mq_unlink("/fuzzer") == -1) perror("mq_unlink");

  return 0;
}
