#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include "fuzzer.h"

auto execute_socketop(prog_t* program) -> void {
  std::vector<uint64_t*> args;
  socket_op_t *sop{nullptr};

  struct iovec iov[1];
  struct msghdr message{};

  for(uint32_t i{0}; i < program->nops; i++)
    args.push_back(parse_data<socket_op_t>(program->op.sock->at(i)));

  for(uint32_t i{0}; i < program->nops; i++) {
    sop = program->op.sock->at(i);

    switch(sop->option) {
      case 0:
      setsockopt(program->fd, SOL_SOCKET, sop->optname, args.at(i), sop->size);
      break;
      case 1:
      write(program->fd, args.at(i), sop->size);
      break;
      case 2:
      iov[0].iov_base = args.at(i);
      iov[0].iov_len = sop->size;
      message.msg_iov = iov;
      message.msg_iovlen = 1;
      sendmsg(program->fd, &message, 0);
      break;
      case 3:
      ioctl(program->fd, sop->request, args.at(i));
      break;
    }
  }

  return;
}
