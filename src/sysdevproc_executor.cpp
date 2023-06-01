#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include "fuzzer.h"

auto execute(sysdevproc_op_t* sdpop) -> void {
  uint64_t *args = new uint64_t[sdpop->nsize+2];

  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

  std::vector<void*> ptrs;

  perstruct_cnt.push_back(0);

  for(uint64_t i{0}; i < sdpop->value.size(); i++) {
    if(!sdpop->sinfo.get_deep(i)) {

      if(i && sdpop->sinfo.get_deep(i) < sdpop->sinfo.get_deep(i-1)) {
        for(uint64_t j{0}; j < sdpop->sinfo.get_deep(i-1) - sdpop->sinfo.get_deep(i); j++) {
          if(!size.size()) break;
          size.pop_back();
          offsets.pop_back();
          perstruct_cnt.pop_back();
        }
      }
      SETVAL(args, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) > sdpop->sinfo.get_deep(i-1)) {

      if(sdpop->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(args);
      }
      for(uint64_t j{0}; j < sdpop->sinfo.get_deep(i) - sdpop->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) == sdpop->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(args);
      SETVAL(args, sdpop->value);

    } else if(i && sdpop->sinfo.get_deep(i) < sdpop->sinfo.get_deep(i-1)) {

      for(uint64_t j{0}; j < sdpop->sinfo.get_deep(i-1) - sdpop->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      if(sdpop->sinfo.get(i, sdpop->sinfo.get_deep(i)) == sdpop->sinfo.get(i-1, sdpop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        SETVAL(args, sdpop->value);

      } else if(sdpop->sinfo.get(i, sdpop->sinfo.get_deep(i)) > sdpop->sinfo.get(i-1, sdpop->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        for(uint64_t j{0}; j < sdpop->sinfo.get_deep(i) - sdpop->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(args);
        }
        SETVAL(args, sdpop->value);

      }
    } else if(sdpop->sinfo.get_deep(i)) {

      for(uint64_t j{0}; j < sdpop->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, sdpop->value);

    }
  }

  switch(sdpop->option) {
    case 0:
    ioctl(sdpop->fd, sdpop->request, args);
    break;
    case 1:
    break;
    read(sdpop->fd, args, sdpop->nsize);
    break;
    case 2:
    write(sdpop->fd, args, sdpop->nsize);
    break;
  }

  for(auto e : ptrs) {
    delete e;
  }

  delete [] args;

  return;
}
