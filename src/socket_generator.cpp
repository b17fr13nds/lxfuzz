#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include <filesystem>
#include <sys/socket.h>
#include "fuzzer.h"

auto open_socket(prog_t *p) -> int {
  int32_t fd{}, domain{}, type{};

  do {
    domain = get_random(0x0,0x17);
    type = get_random(0x0,0x5);
    fd = socket(domain, type, 0);
  } while(fd == -1);

  p->domain = domain;
  p->type = type;

  return fd;
}

auto create_socketop() -> socket_op_t* {
  int32_t max_struct_rand{1}, curr_rand{0};
  uint64_t structure_deep{0};
  std::vector<uint64_t> tmp;

  socket_op_t *sop = new socket_op_t;

  sop->option = get_random(0,3);

  while(1) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = curr_rand;

    sop->value.push_back(get_random(0,0xffffffffffffffff));
    if(sop->option != 3 && !curr_rand) {
      sop->size += 8;
      if(sop->option == 0) {
        sop->optname = get_random(0,0xffffffffffffffff);
      }
    }
    if(curr_rand == max_struct_rand) {
      max_struct_rand++;
    } else if(max_struct_rand > 1) {
      max_struct_rand--;
    }

    sop->sinfo.push(tmp);
    sop->sinfo.push_end(1);
    for(uint64_t j{0}; j < structure_deep; j++) {
      sop->sinfo.push_end(1);

      for(uint64_t i{0}; i < sop->sinfo.get_size()-1; i++) {
        if(j+1 <= sop->sinfo.get_deep(i) && sop->sinfo.get_deep(i)) {
          if(check_smaller_before<socket_op_t>(i, j+1, sop)) sop->sinfo.incr_end(j+1);
        }
      }
    }

    if(!sop->sinfo.get_deep(sop->sinfo.get_size()-1)) break;
  }

  return sop;
}

auto create_program3() -> prog_t* {
  prog_t *program = new prog_t;
  int32_t fd{open_socket(program)};
  auto n{get_random(1,8)};

  program->inuse = 2;
  program->op.sock = new std::vector<socket_op_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sock->push_back(create_socketop());
    program->op.sock->at(i)->fd = fd;
  }

  return program;
}
