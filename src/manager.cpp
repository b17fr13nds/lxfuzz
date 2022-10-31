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
#include "fuzzer.h"

std::vector<int> instances;

auto print_usage_and_exit(char **argv) -> void {
  std::cout << argv[0] << ": <instances>" << std::endl;
  exit(0);
}

auto parse_cmdline(int instance_no) -> const char ** {
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
  int cnt{0};

  for(auto &elem : *v) {
    args[cnt++] = elem.c_str();
  }

  args[cnt] = NULL;
  f.close();

  return args;
}

auto start_instance(int instance_no) -> void {
  int pid{};
  int input_pipefd[2], output_pipefd[2];

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
    if(static_cast<unsigned long>(instance_no) < instances.size()) instances.at(instance_no) = pid; else instances.push_back(pid);

    close(input_pipefd[0]);
    close(output_pipefd[1]);

    char c;
    do {
      if(read(output_pipefd[0], &c, 1) == -1) error("read");
    } while(c != '$');
    if(write(input_pipefd[1], "./fuzzer\n\r", 10) == -1) error("write");
  }

  return;
}

auto check_if_alive(int idx) -> bool {
  if(!waitpid(instances.at(idx), NULL, WNOHANG)) return true;
  return false;
}

auto cleanup(int x) -> void {
  if(mq_unlink("/fuzzer") == -1) perror("mq_unlink");

  exit(0);
}

auto main(int argc, char **argv) -> int {
  auto crashes{0};
  mqd_t desc{0};
  struct mq_attr attr{0x0,0x1,sizeof(stats_t),0x0};

  std::cout << "welcome to uxfuzz v0.0.1" << std::endl;

  if(argc != 2) print_usage_and_exit(argv);

  signal(SIGINT, cleanup);

  desc = mq_open("/fuzzer", O_RDONLY|O_CREAT, S_IRUSR|S_IWOTH, &attr);
  if(desc == -1) error("mq_open");

  std::cout << "starting instances" << std::endl;

  for(auto i{0}; i < std::stoi(argv[1]); i++) {
    std::filesystem::create_directory("./kernel/data/instance" + std::to_string(i));
    start_instance(i);
  }

  std::cout << "instances started; fuzzer ready" << std::endl;
  stats_t tmp{0}, tot{0};

  while(1) {
    tot.execs_per_sec = 0;

    for(auto i{0}; i < std::stoi(argv[1]); i++) {
      if(!check_if_alive(i)) {
        std::cout << "instance " << i << " crashed!" << std::endl;
        crashes++;
        start_instance(i);
        std::cout << "instance " << i << " brought back up!" << std::endl;
      } else {
        if(mq_receive(desc, (char *)&tmp, sizeof(stats_t), 0) == -1) error("mq_receive");

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
