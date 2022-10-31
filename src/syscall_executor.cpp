#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include "fuzzer.h"

template <typename... T>
auto exec_syscall(unsigned short nr, T... args) {
  syscall(nr, args...);
}

auto exec_syscall(unsigned short nr) {
  syscall(nr);
}

auto execute(syscall_t* sysc) -> void {
  unsigned long *args = new unsigned long[sysc->nargs+2];
  size_t tmp{0};
  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

  perstruct_cnt.push_back(0);

  for(unsigned long i{0}; i < sysc->value.size(); i++) {
    if(!sysc->sinfo.get_deep(i)) {

      if(i && sysc->sinfo.get_deep(i) < sysc->sinfo.get_deep(i-1)) {
        for(unsigned long j{0}; j < sysc->sinfo.get_deep(i-1) - sysc->sinfo.get_deep(i); j++) {
          if(!size.size()) break;
          size.pop_back();
          offsets.pop_back();
          perstruct_cnt.pop_back();
        }
      }
      SETVAL(args, sysc->value);

    } else if(i && sysc->sinfo.get_deep(i) > sysc->sinfo.get_deep(i-1)) {

      if(sysc->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(args);
      }

      for(unsigned long j{0}; j < sysc->sinfo.get_deep(i) - sysc->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(args);
      }

      SETVAL(args, sysc->value);

    } else if(i && sysc->sinfo.get_deep(i) == sysc->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(args);
      SETVAL(args, sysc->value);

    } else if(i && sysc->sinfo.get_deep(i) < sysc->sinfo.get_deep(i-1)) {

      for(unsigned long j{0}; j < sysc->sinfo.get_deep(i-1) - sysc->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      if(sysc->sinfo.get(i, sysc->sinfo.get_deep(i)) == sysc->sinfo.get(i-1, sysc->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        SETVAL(args, sysc->value);

      } else if(sysc->sinfo.get(i, sysc->sinfo.get_deep(i)) > sysc->sinfo.get(i-1, sysc->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        for(unsigned long j{0}; j < sysc->sinfo.get_deep(i) - sysc->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(args);
        }
        SETVAL(args, sysc->value);

      }
    } else if(sysc->sinfo.get_deep(i)) {

      for(unsigned long j{0}; j < sysc->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, sysc->value);

    }
  }

  switch(sysc->nargs) {
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
  return;
}
