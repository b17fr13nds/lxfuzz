#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include "fuzzer.h"

auto execute(socket_op_t* sop) -> void {
  struct iovec iov[1];
  struct msghdr message{};
  uint64_t *args = new uint64_t[sop->nsize+2];

  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

  std::vector<void*> ptrs;

  perstruct_cnt.push_back(0);

  for(uint64_t i{0}; i < sop->value.size(); i++) {
    if(!sop->sinfo.get_deep(i)) {

      if(i && sop->sinfo.get_deep(i) < sop->sinfo.get_deep(i-1)) {
        for(uint64_t j{0}; j < sop->sinfo.get_deep(i-1) - sop->sinfo.get_deep(i); j++) {
          if(!size.size()) break;
          size.pop_back();
          offsets.pop_back();
          perstruct_cnt.pop_back();
        }
      }
      SETVAL(args, sop->value);

    } else if(i && sop->sinfo.get_deep(i) > sop->sinfo.get_deep(i-1)) {

      if(sop->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(args);
      }
      for(uint64_t j{0}; j < sop->sinfo.get_deep(i) - sop->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, sop->value);

    } else if(i && sop->sinfo.get_deep(i) == sop->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(args);
      SETVAL(args, sop->value);

    } else if(i && sop->sinfo.get_deep(i) < sop->sinfo.get_deep(i-1)) {

      for(uint64_t j{0}; j < sop->sinfo.get_deep(i-1) - sop->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      if(sop->sinfo.get(i, sop->sinfo.get_deep(i)) == sop->sinfo.get(i-1, sop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        SETVAL(args, sop->value);

      } else if(sop->sinfo.get(i, sop->sinfo.get_deep(i)) > sop->sinfo.get(i-1, sop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        for(uint64_t j{0}; j < sop->sinfo.get_deep(i) - sop->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(args);
        }
        SETVAL(args, sop->value);

      }
    } else if(sop->sinfo.get_deep(i)) {

      for(uint64_t j{0}; j < sop->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, sop->value);

    }
  }

  switch(sop->option) {
    case 0:
    setsockopt(sop->fd, SOL_SOCKET, sop->optname, args, sop->nsize);
    break;
    case 1:
    write(sop->fd, args, sop->nsize);
    break;
    case 2:
    iov[0].iov_base = args;
    iov[0].iov_len = sop->nsize;
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
