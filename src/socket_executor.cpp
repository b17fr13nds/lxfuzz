#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include "fuzzer.h"

auto execute(socket_op_t* sop) -> void {
  struct iovec iov[1];
  struct msghdr message{};
  uint64_t arg{};
  size_t tmp{0};

  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

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
      SETVAL(&arg, sop->value);

    } else if(i && sop->sinfo.get_deep(i) > sop->sinfo.get_deep(i-1)) {

      if(sop->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(&arg);
      }
      for(uint64_t j{0}; j < sop->sinfo.get_deep(i) - sop->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(&arg);
      }
      SETVAL(&arg, sop->value);

    } else if(i && sop->sinfo.get_deep(i) == sop->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(&arg);
      SETVAL(&arg, sop->value);

    } else if(i && sop->sinfo.get_deep(i) < sop->sinfo.get_deep(i-1)) {

      for(uint64_t j{0}; j < sop->sinfo.get_deep(i-1) - sop->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      if(sop->sinfo.get(i, sop->sinfo.get_deep(i)) == sop->sinfo.get(i-1, sop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(&arg);
        SETVAL(&arg, sop->value);

      } else if(sop->sinfo.get(i, sop->sinfo.get_deep(i)) > sop->sinfo.get(i-1, sop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(&arg);
        for(uint64_t j{0}; j < sop->sinfo.get_deep(i) - sop->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(&arg);
        }
        SETVAL(&arg, sop->value);

      }

    } else if(sop->sinfo.get_deep(i)) {

      for(uint64_t j{0}; j < sop->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(&arg);
      }
      SETVAL(&arg, sop->value);

    }
  }

  switch(sop->option) {
    case 0:
    setsockopt(sop->fd, SOL_SOCKET, sop->optname, &arg, sop->size);
    break;
    case 1:
    write(sop->fd, &arg, sop->size);
    break;
    case 2:
    iov[0].iov_base = &arg;
    iov[0].iov_len = sop->size;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    sendmsg(sop->fd, &message, 0);
    break;
    case 3:
    ioctl(sop->fd, sop->request, &arg);
    break;
  }

  return;
}
