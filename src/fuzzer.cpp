#include <iostream>
#include <thread>
#include <string>
#include <random>
#include <chrono>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include "fuzzer.h"
#include "hypercall.h"

std::random_device dev;

auto get_random(unsigned long min, unsigned long max) -> unsigned long {
  std::mt19937_64 rng(dev());

  if(max == 0xffffffffffffffff && get_random(0,1)) {
    min = 0x0;
    max = 0x1000;
  }

  std::uniform_int_distribution<std::mt19937_64::result_type> dist6(min,max);

  return dist6(rng);
}

auto execute_program(prog_t *program) -> void {
  auto pid{fork()};

  switch(pid) {
    case 0:

    for(auto i{0}; i < program->nops; i++) {
      switch(program->inuse) {
        case 0:
        execute(program->op.sysc->at(i));
        break;
        case 1:
        execute(program->op.sdp->at(i));
        break;
        case 2:
        execute(program->op.sock->at(i));
        break;
      }
    }

    [[fallthrough]];
    case -1:
    exit(0);
    default:
    switch(program->inuse) {
      case 1:
      close(program->op.sdp->at(0)->fd);
      break;
      case 2:
      close(program->op.sock->at(0)->fd);
      break;
    }
    return;
  }
}

auto start(int core) -> void {
  prog_t *program{nullptr};
  const char *new_msg = "---------- NEW PROGRAM ----------";
  int rnd{0};

  while(1) {
    flog(static_cast<unsigned long>(core), new_msg);
    rnd = get_random(0,2);
    switch(rnd) {
      case 0:
      program = create_program1();
      for(auto i{0}; i < program->nops; i++) {
        flog(static_cast<unsigned long>(core), program->op.sysc->at(i)->log.c_str());
      }
      break;
      case 1:
      program = create_program2();
      flog(static_cast<unsigned long>(core), program->init_log.c_str());
      for(auto i{0}; i < program->nops; i++) {
        flog(static_cast<unsigned long>(core), program->op.sdp->at(i)->log.c_str());
      }
      break;
      case 2:
      program = create_program3();
      flog(static_cast<unsigned long>(core), program->init_log.c_str());
      for(auto i{0}; i < program->nops; i++) {
        flog(static_cast<unsigned long>(core), program->op.sock->at(i)->log.c_str());
      }
      break;
    }

    execute_program(program);
  }
}

auto main() -> int {
  auto cores_available = std::thread::hardware_concurrency();
  std::thread *t = new std::thread[cores_available];
  auto pid{fork()};

  switch(pid) {
    case 0:
    for(decltype(cores_available) i{0}; i < cores_available; i++) {
      t[i] = std::thread(start, i);
    }
  }

  // afk
  std::string s;
  std::cin >> s;

  return 0;
}
