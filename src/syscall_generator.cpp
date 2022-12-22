#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include "fuzzer.h"

auto create_syscall() -> syscall_t* {
  int32_t nargs{static_cast<int32_t>(get_random(0,6))}, cnt{0}, max_struct_rand{1}, curr_rand{0};
  uint64_t saved{0}, structure_deep{0};
  std::vector<uint64_t> tmp;

  syscall_t *sysc = new syscall_t;

  sysc->sysno = get_random(0,332);

  while(cnt < nargs) {
    sysc->nargno.push_back(nargs);
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<uint64_t>(curr_rand);

    sysc->value.push_back(get_random(0,0xffffffffffffffff));
    if(curr_rand == max_struct_rand) {
      max_struct_rand++;
    } else if(max_struct_rand > 1) {
      max_struct_rand--;
    }

    sysc->sinfo.push(tmp);
    sysc->sinfo.push_end(1);
    for(uint64_t j{0}; j < structure_deep; j++) {
      sysc->sinfo.push_end(1);

      for(uint64_t i{0}; i < sysc->sinfo.get_size()-1; i++) {
        if(j+1 <= sysc->sinfo.get_deep(i) && sysc->sinfo.get_deep(i)) {
          if(check_smaller_before<syscall_t>(i, j+1, sysc)) sysc->sinfo.incr_end(j+1);
        }
      }
    }

    switch(sysc->sinfo.get_deep(sysc->sinfo.get_size()-1)) {
      case 0:
      saved = 0;
      cnt++;
      break;
      case 1:
      if(sysc->sinfo.get_last(sysc->sinfo.structinfo.size()-1) == saved) break;
      saved = sysc->sinfo.get_last(sysc->sinfo.structinfo.size()-1);
      cnt++;
      break;
      default:
      if(sysc->sinfo.get_size()-1 > 1) {
        if(sysc->sinfo.get_deep(sysc->sinfo.get_size()-2) != 0) break;
      } else break;
      cnt++;
      break;
    }
  }

  sysc->nargs = nargs;
  return sysc;
}

auto create_program1() -> prog_t* {
  prog_t *program = new prog_t;
  auto n{get_random(1,8)};

  program->inuse = 0;
  program->op.sysc = new std::vector<syscall_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sysc->push_back(create_syscall());
  }

  return program;
}
