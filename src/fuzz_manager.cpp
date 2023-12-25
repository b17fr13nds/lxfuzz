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

stats_t total_stats{0};
int32_t crashes, instances_ready{0};

auto print_usage_and_exit(char **argv) -> void {
  endwin();
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

  write_screen(5, 15, std::string("qemu cmdline: "));
  int col{5}, line{16};
  while(!f.eof()) {
    getline(f, tmp, '|');

    if(tmp.size() + col > 78) {
      line++;
      col = 5;
    }
    write_screen(col, line, tmp);
    col += tmp.size() + 1;

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
    instances.at(instance_no)->pid = pid;

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

auto stop_instance(int32_t instance_no) -> void {
  if(!instances.at(instance_no)->pid) return;

  if(kill(instances.at(instance_no)->pid, SIGKILL) == -1) error("kill");
  if(waitpid(instances.at(instance_no)->pid, NULL, 0) == -1) error("waitpid");

  instances.at(instance_no)->pid = 0;

  return;
}

auto check_if_alive(int32_t instance_no) -> bool {
  if(!waitpid(instances.at(instance_no)->pid, NULL, WNOHANG)) return true;
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
  endwin();

  for(uint64_t i{0}; i < instances.size(); i++) {
    stop_instance(i);
    if(mq_unlink(("/fuzzer" + std::to_string(i)).c_str()) == -1) error("mq_unlink");
  }

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

auto watch_instance(uint32_t instance_no, std::string fuzzer_args) -> void {
  struct mq_attr attr{0x0,0x1,sizeof(stats_t),0x0};
  mqd_t desc{0};

  std::chrono::steady_clock sc;

  desc = mq_open(("/fuzzer" + std::to_string(instance_no)).c_str(), O_RDONLY|O_CREAT|O_NONBLOCK, S_IRWXU|S_IRWXG|S_IRWXO, &attr);
  if(desc == -1) error("mq_open");

  start_instance(instance_no, fuzzer_args);

  stats_t tmp{0};

  while(1) {
    auto ref = sc.now(); 

retry:
    if(static_cast<std::chrono::duration<double>>(sc.now() - ref).count() > 45.0) {
      if(!check_if_alive(instance_no)) {
        write_screen(44, 8, std::string("instance ") + std::to_string(instance_no) + std::string(" crashed!        "));
        write_screen(6, 2, std::string("instances: up (1 down)"));

        save_crash(instance_no);

        for (const auto& e : std::filesystem::directory_iterator("./kernel/data/instance" + std::to_string(instance_no)))
          std::filesystem::remove_all(e.path());

        start_instance(instance_no, fuzzer_args);

        crashes++;
        instances.at(instance_no)->crashes++;

        write_screen(44, 8, std::string("instance ") + std::to_string(instance_no) + std::string(" brought back up!"));
        write_screen(6, 2, std::string("instances: up         "));
      } else if(!check_if_log_activity(instance_no)) {
        write_screen(44, 8, std::string("instance ") + std::to_string(instance_no) + std::string(" hangs!          "));
        write_screen(6, 2, std::string("instances: up (1 down)"));

        stop_instance(instance_no);

        for(size_t i{0}; i < number_of_files_in_directory("./kernel/data/instance" + std::to_string(instance_no)); i++)
          instances.at(instance_no)->logsizes[i] = 0;

        for (const auto& e : std::filesystem::directory_iterator("./kernel/data/instance" + std::to_string(instance_no)))
          std::filesystem::remove_all(e.path());

        start_instance(instance_no, fuzzer_args);

        write_screen(44, 8, std::string("instance ") + std::to_string(instance_no) + std::string(" brought back up!"));
        write_screen(6, 2, std::string("instances: up         "));
      }
    } else {
      if(mq_receive(desc, (char *)&tmp, sizeof(stats_t), 0) == -1) {
        sleep(1);
        goto retry;
      }

      total_stats.total_execs += tmp.total_execs;
      total_stats.execs_per_sec += tmp.execs_per_sec;
      instances_ready++;
    }
  }
}

auto main(int32_t argc, char **argv) -> int32_t {
  auto ninstances{0};
  std::string fuzzer_args{};

  initscr();
  write_screen(26, 0, std::string("lxfuzz kernel fuzzer (v0.0.1)"));
  write_screen(6, 2, std::string("instances: down"));
  write_screen(59, 2, std::string("fuzzer: starting"));
  write_screen(5, 4, std::string("stats"));
  write_screen(41, 4, std::string("message log"));

  if(argc < 2) print_usage_and_exit(argv);
  
  fuzzer_args = parse_fuzzer_args(&argv[2]);
  ninstances = std::stoi(argv[1]);

  signal(SIGINT, cleanup);

  for(auto i{0}; i < ninstances; i++) {
    std::filesystem::create_directory("./kernel/data/instance" + std::to_string(i));
    instances.push_back(new instance_t);
    instances.back()->crashes = 0;
    instances.back()->logsizes = new uint64_t[number_of_files_in_directory("./kernel/data/instance" + std::to_string(i))];

    for(size_t j{0}; j < number_of_files_in_directory("./kernel/data/instance" + std::to_string(i)); j++)
      instances.back()->logsizes[j] = 0;
  }

  std::thread *t = new std::thread[ninstances];

  for(auto i{0}; i < ninstances; i++) {
    t[i] = std::thread(watch_instance, i, fuzzer_args);
  }

  write_screen(6, 2, std::string("instances: up         "));
  write_screen(59, 2, std::string("fuzzer: running "));

  while(1) {
    total_stats.execs_per_sec = 0;

    while(instances_ready < ninstances) sleep(1);
    instances_ready = 0;

    total_stats.execs_per_sec /= ninstances;    

    write_screen(8, 7, std::string("total execs: ") + std::to_string(total_stats.total_execs));
    write_screen(8, 8, std::string("execs per second: ") + std::to_string(total_stats.execs_per_sec));
    write_screen(8, 9, std::string("crashes: ") + std::to_string(crashes));

    uint64_t total_logsize{0};
    for(auto i{0}; i < ninstances; i++) {
      for(size_t j{0}; j < number_of_files_in_directory("./kernel/data/instance" + std::to_string(i)); j++)
        total_logsize += std::filesystem::file_size("./kernel/data/instance" + std::to_string(i) + "/log_t" + std::to_string(j));
    }

    write_screen(5, 12, std::string("number of instances: ") + std::to_string(ninstances));
    write_screen(5, 13, std::string("total log size: ") + std::to_string(total_logsize) + std::string(" bytes"));
  }

  return 0;
}
