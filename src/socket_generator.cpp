#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include <filesystem>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "fuzzer.h"

auto check_smaller_before(unsigned long start, unsigned long c, socket_op_t* s) -> bool {
  for(long i{static_cast<long>(start)+1}; i >= 0; i--) {
    if(s->sinfo.get_deep(i) >= c) break;
    if(s->sinfo.get_deep(i) < c) return true;
  }
  return false;
}

auto open_socket(prog_t *p) -> int {
  int fd{}, domain{}, type{};

  do {
    domain = get_random(AF_UNIX,AF_XDP);
    type = get_random(SOCK_STREAM,SOCK_RDM);
    fd = socket(domain, type, 0);
  } while(fd == -1);

  p->init_log = "socket(" + std::to_string(domain) + ", " + std::to_string(type) + ", 0);";

  return fd;
}

auto create_socketop() -> socket_op_t* {
  unsigned long structure_deep{0};
  auto max_struct_rand{1}, curr_rand{0};
  std::vector<unsigned long> tmp;
  socket_op_t *sop = new socket_op_t;

  sop->size = 0;

  sop->option = get_random(0,3);
  switch(sop->option) {
    case 0:
    sop->log = "setsockopt(" + std::to_string(sop->fd) + ", SOL_SOCKET, ";
    break;
    case 1:
    sop->log = "send(" + std::to_string(sop->fd) + ", ";
    break;
    case 2:
    sop->log = "sendmsg(" + std::to_string(sop->fd) + ", {.iov.iov_base = ";
    break;
    case 3: // ioctl
    sop->request = get_random(0,0xffffffffffffffff);
    sop->log = "ioctl(" + std::to_string(sop->fd) + ", " + std::to_string(sop->request) + ", ";
    break;
  }

  while(1) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = curr_rand;

    sop->value.push_back(get_random(0,0xffffffffffffffff));
    if(sop->option != 3) {
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
    for(unsigned long j{0}; j < structure_deep; j++) {
      sop->sinfo.push_end(1);

      for(unsigned long i{0}; i < sop->sinfo.get_size()-1; i++) {
        if(j+1 <= sop->sinfo.get_deep(i) && sop->sinfo.get_deep(i)) {
          if(check_smaller_before(i, j+1, sop)) sop->sinfo.incr_end(j+1);
        }
      }
    }

    sop->log += "[v:" + std::to_string(sop->value.back()) + "|d:" + std::to_string(sop->sinfo.get_deep(sop->sinfo.get_size()-1)) + "|n:" + std::to_string(sop->sinfo.get_last()) + "]";

    if(!sop->sinfo.get_deep(sop->sinfo.get_size()-1)) break;
  }

  switch(sop->option) {
    case 2:
    sop->log += ", .iov.len = " + std::to_string(sop->size) + "}, 0);";
    break;
    case 0: [[fallthrough]];
    case 1: 
    sop->log += ", " + std::to_string(sop->size);
    default:
    sop->log += ");";
  }

  return sop;
}

auto create_program3() -> prog_t* {
  prog_t *program = new prog_t;
  auto n{static_cast<int>(get_random(1,8))}, fd{open_socket(program)};

  program->inuse = 2;
  program->op.sock = new std::vector<socket_op_t*>;
  program->nops = n;

  for(auto i{0}; i < n; i++) {
    program->op.sock->push_back(create_socketop());
    program->op.sock->at(i)->fd = fd;
  }

  return program;
}
