#include <iostream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <random>
#include <filesystem>
#include "fuzzer.h"


auto open_device(prog_t *p) -> int {
  int fd{}, tmp{};
  std::string path, log;
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
    p->prot = O_RDWR;
    if(fd == -1) {
      fd = open(devnames.at(tmp).c_str(), O_RDONLY);
      p->prot = O_RDONLY;
    }
  } while(fd == -1);

  p->devname = devnames.at(tmp);

  return fd;
}

auto create_sysdevprocop() -> sysdevproc_op_t* {
  int max_struct_rand{1}, curr_rand{0};
  unsigned long structure_deep{0};
  std::vector<unsigned long> tmp;
  sysdevproc_op_t *sdpop = new sysdevproc_op_t;

  sdpop->option = get_random(0,2);

  while(1) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<unsigned long>(curr_rand);

    sdpop->value.push_back(get_random(0,0xffffffffffffffff));
    if(sdpop->option != 0 && !curr_rand)
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
          if(check_smaller_before<sysdevproc_op_t>(i, j+1, sdpop)) sdpop->sinfo.incr_end(j+1);
        }
      }
    }

    if(!sdpop->sinfo.get_deep(sdpop->sinfo.get_size()-1)) break;
  }

  return sdpop;
}

auto create_program2() -> prog_t* {
  prog_t *program = new prog_t;
  int fd{open_device(program)};
  auto n{get_random(1,8)};

  program->inuse = 1;
  program->op.sdp = new std::vector<sysdevproc_op_t*>;
  program->nops = n;

  for(decltype(n) i{0}; i < n; i++) {
    program->op.sdp->push_back(create_sysdevprocop());
    program->op.sdp->at(i)->fd = fd;
  }

  return program;
}
