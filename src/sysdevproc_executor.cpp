#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/ioctl.h>
#include "fuzzer.h"

auto execute(sysdevproc_op_t* sdpop) -> void {
  unsigned long arg{};
  size_t tmp{0};
  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

  perstruct_cnt.push_back(0);

  for(unsigned long i{0}; i < sdpop->value.size(); i++) {
    if(!sdpop->sinfo.get_deep(i)) {

      if(i && sdpop->sinfo.get_deep(i) < sdpop->sinfo.get_deep(i-1)) {
        for(unsigned long j{0}; j < sdpop->sinfo.get_deep(i-1) - sdpop->sinfo.get_deep(i); j++) {
          if(!size.size()) break;
          size.pop_back();
          offsets.pop_back();
          perstruct_cnt.pop_back();
        }
      }
      SETVAL(&arg, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) > sdpop->sinfo.get_deep(i-1)) {

      if(sdpop->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(&arg);
      }

      for(unsigned long j{0}; j < sdpop->sinfo.get_deep(i) - sdpop->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(&arg);
      }

      SETVAL(&arg, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) == sdpop->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(&arg);
      SETVAL(&arg, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) < sdpop->sinfo.get_deep(i-1)) {

      for(unsigned long j{0}; j < sdpop->sinfo.get_deep(i-1) - sdpop->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      if(sdpop->sinfo.get(i, sdpop->sinfo.get_deep(i)) == sdpop->sinfo.get(i-1, sdpop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(&arg);
        SETVAL(&arg, sdpop->value);

      } else if(sdpop->sinfo.get(i, sdpop->sinfo.get_deep(i)) > sdpop->sinfo.get(i-1, sdpop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(&arg);
        for(unsigned long j{0}; j < sdpop->sinfo.get_deep(i) - sdpop->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(&arg);
        }
        SETVAL(&arg, sdpop->value);

      }
    } else if(sdpop->sinfo.get_deep(i)) {

      for(unsigned long j{0}; j < sdpop->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(&arg);
      }
      SETVAL(&arg, sdpop->value);

    }
  }

  switch(sdpop->option) {
    case 0:
    ioctl(sdpop->fd, sdpop->request, &arg);
    break;
    case 1:
    if(read(sdpop->fd, &arg, sdpop->size) == -1) error("read");
    break;
    case 2:
    if(write(sdpop->fd, &arg, sdpop->size) == -1) error("write");
    break;
  }
  return;
}
