#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include "fuzzer.h"

auto check_smaller_before(unsigned long start, unsigned long c, syscall_t* s) -> bool {
  for(long i{static_cast<long>(start)+1}; i >= 0; i--) {
    if(s->sinfo.get_deep(i) >= c) break;
    if(s->sinfo.get_deep(i) < c) return true;
  }
  return false;
}

auto create_syscall() -> syscall_t* {
  auto nargs{static_cast<int>(get_random(0,6))}, cnt{0}, max_struct_rand{1}, curr_rand{0};
  unsigned long saved{0}, structure_deep{0};
  std::vector<unsigned long> tmp;
  syscall_t *sysc = new syscall_t;

  sysc->sysno = get_random(0,332);
  sysc->log = "syscall(" + std::to_string(sysc->sysno);

  while(cnt < nargs) {
    sysc->log += ", ";
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<unsigned long>(curr_rand);

    sysc->value.push_back(get_random(0,0xffffffffffffffff));
    if(curr_rand == max_struct_rand) {
      max_struct_rand++;
    } else if(max_struct_rand > 1) {
      max_struct_rand--;
    }

    sysc->sinfo.push(tmp);
    sysc->sinfo.push_end(1);
    for(unsigned long j{0}; j < structure_deep; j++) {
      sysc->sinfo.push_end(1);

      for(unsigned long i{0}; i < sysc->sinfo.get_size()-1; i++) {
        if(j+1 <= sysc->sinfo.get_deep(i) && sysc->sinfo.get_deep(i)) {
          if(check_smaller_before(i, j+1, sysc)) sysc->sinfo.incr_end(j+1);
        }
      }
    }

    sysc->log += "[v:" + std::to_string(sysc->value.back()) + "|d:" + std::to_string(sysc->sinfo.get_deep(sysc->sinfo.get_size()-1)) + "|n:" + std::to_string(sysc->sinfo.get_last()) + "]";

    switch(sysc->sinfo.get_deep(sysc->sinfo.get_size()-1)) {
      case 0:
      saved = 0;
      cnt++;
      break;
      case 1:
      if(sysc->sinfo.get_last() == saved) break;
      saved = sysc->sinfo.get_last();
      cnt++;
      break;
      default:
      if(sysc->sinfo.get_size()-1 > 1) {
        if(sysc->sinfo.get_deep(sysc->sinfo.get_size()-2) != 0) break;
      } else break;
      cnt++;
    }
  }

  sysc->log += ");";

  sysc->nargs = nargs;
  return sysc;
}

auto create_program1() -> prog_t* {
  auto n{get_random(1,8)};
  prog_t *program = new prog_t;

  program->inuse = 0;
  program->op.sysc = new std::vector<syscall_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sysc->push_back(create_syscall());
  }

  return program;
}
