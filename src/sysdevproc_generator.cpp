#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include <filesystem>
#include <fcntl.h>
#include "fuzzer.h"

auto check_smaller_before(unsigned long start, unsigned long c, sysdevproc_op_t* s) -> bool {
  for(long i{static_cast<long>(start)+1}; i >= 0; i--) {
    if(s->sinfo.get_deep(i) >= c) break;
    if(s->sinfo.get_deep(i) < c) return true;
  }
  return false;
}

auto open_device(prog_t *p) -> int {
  int fd{}, tmp{};
  std::string path, prot, log;
  std::vector<std::string> devnames;

  path = "/dev";
  for(auto& entry : std::filesystem::directory_iterator(path))
    devnames.push_back(entry.path());

  path = "/proc";
  for(auto& entry : std::filesystem::directory_iterator(path))
    devnames.push_back(entry.path());

  path = "/sys/class";
  for(auto& entry : std::filesystem::recursive_directory_iterator(path))
    devnames.push_back(entry.path());

  do {
    tmp = get_random(0, devnames.size()-1);
    fd = open(devnames.at(tmp).c_str(), O_RDWR);
    prot = "O_RDWR";
    if(fd == -1) {
      fd = open(devnames.at(tmp).c_str(), O_RDONLY);
      prot = "O_RDONLY";
    }
  } while(fd == -1);

  p->init_log = "open(" + devnames.at(tmp) + ", " + prot + ");";

  return fd;
}

auto create_sysdevprocop() -> sysdevproc_op_t* {
  unsigned long structure_deep{0};
  auto max_struct_rand{1}, curr_rand{0};
  std::vector<unsigned long> tmp;
  sysdevproc_op_t *sdpop = new sysdevproc_op_t;

  sdpop->size = 0;

  sdpop->option = get_random(0,2);
  switch(sdpop->option) {
    case 0: // ioctl
    sdpop->request = get_random(0,0xffffffffffffffff);
    sdpop->log = "ioctl(" + std::to_string(sdpop->fd) + ", " + std::to_string(sdpop->request) + ", ";
    break;
    case 1:
    sdpop->log = "read(" + std::to_string(sdpop->fd) + ", ";
    break;
    case 2:
    sdpop->log = "write(" + std::to_string(sdpop->fd) + ", ";
    break;
  }

  while(1) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<unsigned long>(curr_rand);

    sdpop->value.push_back(get_random(0,0xffffffffffffffff));
    if(sdpop->option != 0)
      sdpop->size += 8;

    if(curr_rand == max_struct_rand) {
      max_struct_rand++;
    } else if(max_struct_rand > 1) {
      max_struct_rand--;
    }

    sdpop->sinfo.push(tmp);
    sdpop->sinfo.push_end(1);
    for(unsigned long j{0}; j < structure_deep; j++) {
      sdpop->sinfo.push_end(1);

      for(unsigned long i{0}; i < sdpop->sinfo.get_size()-1; i++) {
        if(j+1 <= sdpop->sinfo.get_deep(i) && sdpop->sinfo.get_deep(i)) {
          if(check_smaller_before(i, j+1, sdpop)) sdpop->sinfo.incr_end(j+1);
        }
      }
    }

    sdpop->log += "[v:" + std::to_string(sdpop->value.back()) + "|d:" + std::to_string(sdpop->sinfo.get_deep(sdpop->sinfo.get_size()-1)) + "|n:" + std::to_string(sdpop->sinfo.get_last()) + "]";

    if(!sdpop->sinfo.get_deep(sdpop->sinfo.get_size()-1)) break;
  }

  switch(sdpop->option) {
    case 1: [[fallthrough]];
    case 2: 
    sdpop->log += ", " + std::to_string(sdpop->size);
    default:
    sdpop->log += ");";
    break;
  }

  return sdpop;
}

auto create_program2() -> prog_t* {
  prog_t *program = new prog_t;
  auto n{static_cast<int>(get_random(1,8))}, fd{open_device(program)};

  program->inuse = 1;
  program->op.sdp = new std::vector<sysdevproc_op_t*>;
  program->nops = n;

  for(auto i{0}; i < n; i++) {
    program->op.sdp->push_back(create_sysdevprocop());
    program->op.sdp->at(i)->fd = fd;
  }

  return program;
}
