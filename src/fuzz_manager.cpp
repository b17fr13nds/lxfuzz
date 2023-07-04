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

std::vector<int32_t> instance_pid;
std::vector<int32_t> instance_crashes;

auto print_usage_and_exit(char **argv) -> void {
  std::cout << argv[0] << ": <instances> <fuzzer options...>" << std::endl;
  exit(0);
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

auto start_instance(int32_t instance_no, std::string fuzzer_args) -> void {
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
    if(static_cast<uint64_t>(instance_no) < instance_pid.size()) instance_pid.at(instance_no) = pid; else instance_pid.push_back(pid);

    close(input_pipefd[0]);
    close(output_pipefd[1]);

    char c{};
    do {
      if(read(output_pipefd[0], &c, 1) == -1) error("read");
    } while(c != '$');

    std::string cmd{"./fuzzer " + fuzzer_args + "\n\r"};

    if(write(input_pipefd[1], cmd.c_str(), cmd.size()) == -1) error("write");
    
    close(input_pipefd[1]);
    close(output_pipefd[0]);
  }

  return;
}

auto check_if_alive(int32_t idx) -> bool {
  if(!waitpid(instance_pid.at(idx), NULL, WNOHANG)) return true;
  return false;
}

auto save_crash(int32_t instance_no) -> void {
  std::filesystem::copy("./kernel/data/instance" + std::to_string(instance_no), "./kernel/data/instance" + std::to_string(instance_no) + "_crash" + std::to_string(instance_crashes.at(instance_no))); 
}

auto cleanup(int32_t x) -> void {
  if(mq_unlink("/fuzzer") == -1) perror("mq_unlink");

  exit(0);
}

auto parse_fuzzer_args(char **start) -> std::string {
  std::string ret{};

  for(int i{0}; start[i] != NULL; i++) {
    ret += start[i];
    ret += "";
  }

  return ret;
}

auto main(int32_t argc, char **argv) -> int32_t {
  auto crashes{0};
  mqd_t desc{0};
  struct mq_attr attr{0x0,0x1,sizeof(stats_t),0x0};
  std::string fuzzer_args{};

  std::cout << "welcome to lxfuzz v0.0.1" << std::endl;

  if(argc < 2) print_usage_and_exit(argv);
  fuzzer_args = parse_fuzzer_args(&argv[2]);

  signal(SIGINT, cleanup);

  desc = mq_open("/fuzzer", O_RDONLY|O_CREAT|O_NONBLOCK, S_IRWXU|S_IRWXG|S_IRWXO, &attr);
  if(desc == -1) error("mq_open");

  std::cout << "starting instance" << std::endl;

  for(auto i{0}; i < std::stoi(argv[1]); i++) {
    std::filesystem::create_directory("./kernel/data/instance" + std::to_string(i));
    start_instance(i, fuzzer_args);
    instance_crashes.push_back(0);
  }

  std::cout << "instance started; fuzzer ready" << std::endl;
  stats_t tmp{0}, tot{0};

  while(1) {
    tot.execs_per_sec = 0;

retry:
    for(auto i{0}; i < std::stoi(argv[1]); i++) {
      if(!check_if_alive(i)) {
        std::cout << "instance " << i << " crashed!" << std::endl;

        save_crash(i);

        for (const auto& e : std::filesystem::directory_iterator("./kernel/data/instance" + std::to_string(i))) 
          std::filesystem::remove_all(e.path());

        start_instance(i, fuzzer_args);

        crashes++;
        instance_crashes.at(i)++;

        std::cout << "instance " << i << " brought back up!" << std::endl;
      } else {
        if(mq_receive(desc, (char *)&tmp, sizeof(stats_t), 0) == -1) goto retry;

        tot.total_execs += tmp.total_execs;
        tot.execs_per_sec += tmp.execs_per_sec;
      }
    }

    tot.execs_per_sec /= std::stoi(argv[1]);

    std::cout << "total execs: " << tot.total_execs << std::endl;
    std::cout << "execs per second: " << tot.execs_per_sec << std::endl;
    std::cout << "crashes: " << crashes << std::endl;
  }

  if(mq_unlink("/fuzzer") == -1) perror("mq_unlink");

  return 0;
}
