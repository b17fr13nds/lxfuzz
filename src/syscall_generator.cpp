#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include "fuzzer.h"

auto create_syscall() -> syscall_op_t* {
  int32_t args{static_cast<int32_t>(get_random(0,6))};

  syscall_op_t *sysc = new syscall_op_t;

  sysc->sysno = get_random(0,332);

  create_data<syscall_op_t>(sysc, args);

  return sysc;
}

auto create_program1() -> prog_t* {
  prog_t *program = new prog_t;
  auto n{get_random(1,8)};

  program->inuse = SYSCALL;
  program->op.sysc = new std::vector<syscall_op_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sysc->push_back(create_syscall());
  }

  return program;
}
