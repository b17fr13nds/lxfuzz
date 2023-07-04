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
#include "repro_manager.h"

int32_t pid{0};

auto print_usage_and_exit(char **argv) -> void {
  std::cout << argv[0] << ": <fuzzer options...>" << std::endl;
  exit(0);
}

auto parse_cmdline() -> const char ** {
  std::ifstream f;
  std::string tmp;
  std::vector<std::string> *v = new std::vector<std::string>;

  f.open("./cmdline.cfg");

  while(!f.eof()) {
    getline(f, tmp, '|');
    v->push_back(tmp);
  }

  const char **args{new const char *[v->size()+1]};
  int32_t cnt{0};

  for(auto &elem : *v) {
    args[cnt++] = elem.c_str();
  }

  args[cnt] = NULL;
  f.close();

  return args;
}

auto start_instance(std::string fuzzer_args) -> void {
  int32_t input_pipefd[2], output_pipefd[2];

  const char **args = parse_cmdline();

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

    close(input_pipefd[0]);
    close(output_pipefd[1]);

    char c{};
    do {
      if(read(output_pipefd[0], &c, 1) == -1) error("read");
    } while(c != '$');

    std::string cmd{"./reproducer " + fuzzer_args + "\n\r"};

    if(write(input_pipefd[1], cmd.c_str(), cmd.size()) == -1) error("write");
  }

  return;
}

auto check_if_alive(int32_t pid) -> bool {
  if(!waitpid(pid, NULL, WNOHANG)) return true;
  return false;
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
  std::string fuzzer_args{};

  std::cout << "welcome to lxfuzz v0.0.1" << std::endl;

  if(argc < 1) print_usage_and_exit(argv);
  fuzzer_args = parse_fuzzer_args(&argv[1]);

  std::cout << "starting instance" << std::endl;

  start_instance(fuzzer_args);

  std::cout << "instances started; reproducer ready" << std::endl;

  while(1) {
    if(!check_if_alive(pid)) {
      std::cout << "instance crashed!" << std::endl;
      break;
    }
  }

  return 0;
}
