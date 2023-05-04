#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include "fuzzer.h"

auto open_device(prog_t *p) -> int {
  int fd{}, tmp{};

  do {
    tmp = get_random(0, virtual_dev_names.size()-1);
    fd = open(virtual_dev_names.at(tmp).c_str(), O_RDWR);
    p->prot = O_RDWR;
    if(fd == -1) {
      fd = open(virtual_dev_names.at(tmp).c_str(), O_RDONLY);
      p->prot = O_RDONLY;
    }
  } while(fd == -1);

  p->devname = virtual_dev_names.at(tmp);

  return fd;
}

auto create_sysdevprocop() -> sysdevproc_op_t* {
  int32_t nsize{static_cast<int32_t>(get_random(1,6))}, cnt{0}, max_struct_rand{1}, curr_rand{0};
  unsigned long saved{0}, structure_deep{0};
  std::vector<unsigned long> tmp;

  sysdevproc_op_t *sdpop = new sysdevproc_op_t;

  sdpop->option = get_random(0,2);

  while(cnt < nsize) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<uint64_t>(curr_rand);

    sdpop->value.push_back(get_random(0,0xffffffffffffffff));
    if(curr_rand == max_struct_rand) {
      max_struct_rand++;
    } else if(max_struct_rand > 1) {
      max_struct_rand--;
    }

    sdpop->sinfo.push(tmp);
    sdpop->sinfo.push_end(1);
    for(uint64_t j{0}; j < structure_deep; j++) {
      sdpop->sinfo.push_end(1);

      for(uint64_t i{0}; i < sdpop->sinfo.get_size()-1; i++) {
        if(j+1 <= sdpop->sinfo.get_deep(i) && sdpop->sinfo.get_deep(i)) {
          if(check_smaller_before<sysdevproc_op_t>(i, j+1, sdpop)) sdpop->sinfo.incr_end(j+1);
        }
      }
    }

    switch(sdpop->sinfo.get_deep(sdpop->sinfo.get_size()-1)) {
      case 0:
      saved = 0;
      cnt++;
      break;
      case 1:
      if(sdpop->sinfo.get_last(sdpop->sinfo.structinfo.size()-1) == saved) break;
      saved = sdpop->sinfo.get_last(sdpop->sinfo.structinfo.size()-1);
      cnt++;
      break;
      default:
      if(sdpop->sinfo.get_size()-1 > 1) {
        if(sdpop->sinfo.get_deep(sdpop->sinfo.get_size()-2) != 0) break;
      } else break;
      cnt++;
      break;
    }
  }

  sdpop->nsize = nsize;
  return sdpop;
}

auto create_program2() -> prog_t* {
  prog_t *program = new prog_t;
  int fd{open_device(program)};
  auto n{get_random(1,8)};

  std::cout << "FINISHED OPENING" << std::endl;

  program->inuse = 1;
  program->op.sdp = new std::vector<sysdevproc_op_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sdp->push_back(create_sysdevprocop());
    program->op.sdp->at(i)->fd = fd;
  }

  std::cout << "FINISHED CREATING CALL" << std::endl;

  return program;
}
