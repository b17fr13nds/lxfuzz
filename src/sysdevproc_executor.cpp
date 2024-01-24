#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include "fuzzer.h"

auto execute_sysdevprocop(prog_t* program) -> void {
  std::vector<uint64_t*> args;
  sysdevproc_op_t *sdpop{nullptr};

  for(uint32_t i{0}; i < program->nops; i++)
    args.push_back(parse_data<sysdevproc_op_t>(program->op.sdp->at(i)));

  for(uint32_t i{0}; i < program->nops; i++) {
    sdpop = program->op.sdp->at(i);

    switch(sdpop->option) {
      case 0:
      ioctl(program->fd, sdpop->request, args.at(i));
      break;
      case 1:
      break;
      read(program->fd, args.at(i), sdpop->size);
      break;
      case 2:
      write(program->fd, args.at(i), sdpop->size);
      break;
    }
  }

  return;
}
