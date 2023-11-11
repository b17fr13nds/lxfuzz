#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include "fuzzer.h"

auto execute(sysdevproc_op_t* sdpop) -> void {
  std::vector<void*> ptrs;
  uint64_t *args{parse_data<sysdevproc_op_t>(sdpop, &ptrs)};

  switch(sdpop->option) {
    case 0:
    ioctl(sdpop->fd, sdpop->request, args);
    break;
    case 1:
    break;
    read(sdpop->fd, args, sdpop->size);
    break;
    case 2:
    write(sdpop->fd, args, sdpop->size);
    break;
  }

  for(auto e : ptrs) {
    delete e;
  }

  delete [] args;

  return;
}
