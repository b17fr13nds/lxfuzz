#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include "fuzzer.h"

auto execute(socket_op_t* sop) -> void {
  struct iovec iov[1];
  struct msghdr message{};
  
  std::vector<void*> ptrs;
  uint64_t *args{parse_data<socket_op_t>(sop, &ptrs)};

  switch(sop->option) {
    case 0:
    setsockopt(sop->fd, SOL_SOCKET, sop->optname, args, sop->size);
    break;
    case 1:
    write(sop->fd, args, sop->size);
    break;
    case 2:
    iov[0].iov_base = args;
    iov[0].iov_len = sop->size;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    sendmsg(sop->fd, &message, 0);
    break;
    case 3:
    ioctl(sop->fd, sop->request, args);
    break;
  }

  for(auto e : ptrs) {
    delete e;
  }

  delete [] args;

  return;
}
