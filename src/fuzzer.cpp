#include <iostream>
#include <thread>
#include <string>
#include <random>
#include <chrono>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "fuzzer.h"
#include "hypercall.h"

std::random_device dev;

auto get_random(uint64_t min, uint64_t max) -> uint64_t {
  std::mt19937_64 rng(dev());

  if(max == 0xffffffffffffffff && get_random(0,1)) {
    min = 0x0;
    max = 0x1000;
  }

  std::uniform_int_distribution<std::mt19937_64::result_type> dist6(min,max);

  return dist6(rng);
}

auto flog_program(prog_t *p, int32_t core) -> void {
  std::string log = "";
  uint64_t tmp{0};

  switch(p->inuse) {
    case 0:
    flog(static_cast<uint64_t>(core), "---------------- NEW PROGRAM (syscall) ----------------");
    for(uint64_t i{0}; i < p->nops; i++) {
      log += "syscall(" + std::to_string(p->op.sysc->at(i)->sysno);
      if(p->op.sysc->at(i)->nargs) log += ", ";
      for(uint64_t j{0}; j < p->op.sysc->at(i)->value.size(); j++) {
        log +=  "[v:" + std::to_string(p->op.sysc->at(i)->value.at(j)) + "|d:" + std::to_string(p->op.sysc->at(i)->sinfo.get_deep(j)) + "|n:" + std::to_string(p->op.sysc->at(i)->sinfo.get_last(j)) + "]";
        if(tmp < p->op.sysc->at(i)->nargno.at(j) && j >= p->op.sysc->at(i)->value.size()-1) log += ", ";
        tmp = p->op.sysc->at(i)->nargno.at(j);
      }
      log += ");";
      flog(static_cast<uint64_t>(core), log.c_str());
      log = "";
    }
    break;
    case 1: //sdp
    flog(static_cast<uint64_t>(core), "---------------- NEW PROGRAM (sysdevproc) ----------------");
    log += "fd = open(\"" + p->devname + "\", " + std::to_string(p->prot) + ");";
    flog(static_cast<uint64_t>(core), log.c_str());
    log = "";
    for(uint64_t i{0}; i < p->nops; i++) {
      switch(p->op.sdp->at(i)->option) {
        case 0: // ioctl
        log += "ioctl(fd, " + std::to_string(p->op.sdp->at(i)->request) + ", ";
        break;
        case 1:
        log += "read(fd, ";
        break;
        case 2:
        log += "write(fd, ";
        break;
      }
      for(uint64_t j{0}; j < p->op.sdp->at(i)->value.size(); j++) {
        log +=  "[v:" + std::to_string(p->op.sdp->at(i)->value.at(j)) + "|d:" + std::to_string(p->op.sdp->at(i)->sinfo.get_deep(j)) + "|n:" + std::to_string(p->op.sdp->at(i)->sinfo.get_last(j)) + "]";
      }
      switch(p->op.sdp->at(i)->option) {
        case 1: [[fallthrough]];
        case 2:
        log += ", " + std::to_string(p->op.sdp->at(i)->size);
        break;
      }
      log += ");";
      flog(static_cast<uint64_t>(core), log.c_str());
      log = "";
    }
    break;
    case 2:
    flog(static_cast<uint64_t>(core), "---------------- NEW PROGRAM (socket) ----------------");
    log += "fd = socket(" + std::to_string(p->domain) + ", " + std::to_string(p->type) + ", 0);";
    flog(static_cast<uint64_t>(core), log.c_str());
    log = "";
    for(uint64_t i{0}; i < p->nops; i++) {
      switch(p->op.sock->at(i)->option) {
        case 0:
        log += "setsockopt(fd, SOL_SOCKET, ";
        break;
        case 1:
        log += "write(fd, ";
        break;
        case 2:
        log += "sendmsg(fd, {.iov.iov_base = ";
        break;
        case 3: // ioctl
        log += "ioctl(fd, " + std::to_string(p->op.sock->at(i)->request) + ", ";
        break;
      }
      for(uint64_t j{0}; j < p->op.sock->at(i)->value.size(); j++) {
        log +=  "[v:" + std::to_string(p->op.sock->at(i)->value.at(j)) + "|d:" + std::to_string(p->op.sock->at(i)->sinfo.get_deep(j)) + "|n:" + std::to_string(p->op.sock->at(i)->sinfo.get_last(j)) + "]";
      }
      switch(p->op.sock->at(i)->option) {
        case 2:
        log += ", .iov.len = " + std::to_string(p->op.sock->at(i)->size) + "}, 0);";
        break;
        case 0: [[fallthrough]];
        case 1:
        log += ", " + std::to_string(p->op.sock->at(i)->size);
        default:
        log += ");";
        break;
      }
      flog(static_cast<uint64_t>(core), log.c_str());
      log = "";
    }
    break;
  }

  return;
}

auto execute_program(prog_t *program) -> void {
  auto pid{fork()};

  switch(pid) {
    case 0:

    for(auto i{0}; i < program->nops; i++) {
      switch(program->inuse) {
        case 0:
        execute(program->op.sysc->at(i));
        break;
        case 1:
        execute(program->op.sdp->at(i));
        break;
        case 2:
        execute(program->op.sock->at(i));
        break;
      }
    }

    [[fallthrough]];
    case -1:
    exit(0);
    default:
    return;
  }
}

auto start(int32_t core, fuzzinfo_t fi) -> void {
  prog_t *program{nullptr};
  uint64_t ncovered{0}, prev_ncovered{0}, prev_addr_covered{0};

  while(1) {
    // generation
    if(!(fi.get_corpus_count() > 0x1000)) {
      for(int32_t i{0}; i < 0x10; i++) {
        auto rnd{get_random(0,2)};

        switch(rnd) {
          case 0:
          program = create_program1();
          break;
          case 1:
          program = create_program2();
          break;
          case 2:
          program = create_program3();
          break;
        }
        fi.add_corpus(program);
      }
    }

    // mutation
    for(int32_t i{0}; i < 0x10; i++) {
      program = fi.get_corpus();
      flog_program(program, core);

      fi.record_coverage(core);
      execute_program(program);
      fstats(fi.get_corpus_count());
      ncovered = fi.stop_recording(core);

      prev_ncovered = ncovered;
      prev_addr_covered = fi.get_address(core, ncovered);

      if(!program->nops) {
        delete program;
        continue;
      }

      mutate_prog(program);
      flog_program(program, core);

      fi.record_coverage(core);
      execute_program(program);
      fstats(fi.get_corpus_count());
      ncovered = fi.stop_recording(core);

      if(ncovered > prev_ncovered || (ncovered <= prev_ncovered && fi.get_address(core, ncovered) != prev_addr_covered)) {
        fi.add_corpus(program);
      } else {
        delete program;
      }
    }
  }
}

auto main() -> int32_t {
  auto cores_available = std::thread::hardware_concurrency();
  std::thread *t = new std::thread[cores_available];
  fuzzinfo_t fi(cores_available);

  for(decltype(cores_available) i{0}; i < cores_available; i++) {
      t[i] = std::thread(start, i, fi);
  }

  std::string x;
  std::cin >> x;

  return 0;
}
