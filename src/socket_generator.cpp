#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include <filesystem>
#include <sys/socket.h>
#include "fuzzer.h"

auto open_socket(prog_t *p) -> int32_t {
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
  int32_t size{static_cast<int32_t>(get_random(1,6))};

  socket_op_t *sop = new socket_op_t;

  sop->option = get_random(0,2);

  create_data<socket_op_t>(sop, size);
  
  return sop;
}

auto create_program3() -> prog_t* {
  prog_t *program = new prog_t;
  auto n{get_random(1,8)};

  program->inuse = SOCKET;
  program->op.sock = new std::vector<socket_op_t*>;
  program->nops = n;
  program->fd = open_socket(program);

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sock->push_back(create_socketop());
  }

  return program;
}
