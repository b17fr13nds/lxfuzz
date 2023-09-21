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
  int32_t size{static_cast<int32_t>(get_random(1,6))};

  sysdevproc_op_t *sdpop = new sysdevproc_op_t;

  sdpop->option = get_random(0,2);

  create_data<sysdevproc_op_t>(sdpop, size);

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
