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

auto execute(syscall_op_t* sysc) -> void {
  std::vector<void*> ptrs;
  uint64_t *args{parse_data<syscall_op_t>(sysc, &ptrs)};

  switch(sysc->size) {
    case 0:
    exec_syscall(sysc->sysno);
    break;
    case 1:
    exec_syscall(sysc->sysno, args[0]);
    break;
    case 2:
    exec_syscall(sysc->sysno, args[0], args[1]);
    break;
    case 3:
    exec_syscall(sysc->sysno, args[0], args[1], args[2]);
    break;
    case 4:
    exec_syscall(sysc->sysno, args[0], args[1], args[2], args[3]);
    break;
    case 5:
    exec_syscall(sysc->sysno, args[0], args[1], args[2], args[3], args[4]);
    break;
    case 6:
    exec_syscall(sysc->sysno, args[0], args[1], args[2], args[3], args[4], args[5]);
    break;
  }

  for(auto e : ptrs) {
    delete e;
  }

  delete [] args;

  return;
}
