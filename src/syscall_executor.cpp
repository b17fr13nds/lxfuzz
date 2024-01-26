#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include "fuzzer.h"

template <typename... T>
auto exec_syscall(uint16_t nr, T... args) -> void {
  syscall(nr, args...);
  return;
}

auto exec_syscall(uint16_t nr) -> void {
  syscall(nr);
  return;
}

auto execute_syscallop(prog_t* program) -> void {
  std::vector<uint64_t*> args;
  syscall_op_t *sysc{nullptr};

  for(uint32_t i{0}; i < program->nops; i++)
    args.push_back(parse_data<syscall_op_t>(program->op.sysc->at(i)));

  for(uint32_t i{0}; i < program->nops; i++) {
    sysc = program->op.sysc->at(i);

    switch(sysc->size) {
      case 0:
      exec_syscall(sysc->sysno);
      break;
      case 1:
      exec_syscall(sysc->sysno, args.at(i)[0]);
      break;
      case 2:
      exec_syscall(sysc->sysno, args.at(i)[0], args.at(i)[1]);
      break;
      case 3:
      exec_syscall(sysc->sysno, args.at(i)[0], args.at(i)[1], args.at(i)[2]);
      break;
      case 4:
      exec_syscall(sysc->sysno, args.at(i)[0], args.at(i)[1], args.at(i)[2], args.at(i)[3]);
      break;
      case 5:
      exec_syscall(sysc->sysno, args.at(i)[0], args.at(i)[1], args.at(i)[2], args.at(i)[3], args.at(i)[4]);
      break;
      case 6:
      exec_syscall(sysc->sysno, args.at(i)[0], args.at(i)[1], args.at(i)[2], args.at(i)[3], args.at(i)[4], args.at(i)[5]);
      break;
    }
  }

  return;
}
