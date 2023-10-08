#include <iostream>
#include <thread>
#include <string>
#include <random>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <type_traits>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "fuzzer.h"
#include "hypercall.h"

std::random_device dev;
std::vector<std::string> virtual_dev_names;

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

  switch(p->inuse) {
    case SYSCALL:
    flog(static_cast<uint64_t>(core), "---------------- NEW PROGRAM (syscall) ----------------");
    for(uint64_t i{0}; i < p->nops; i++) {
      log += "syscall(" + std::to_string(p->op.sysc->at(i)->sysno);
      if(p->op.sysc->at(i)->size) log += ", ";
      for(uint64_t j{0}; j < p->op.sysc->at(i)->value.size(); j++) {
        log +=  "[v:" + std::to_string(p->op.sysc->at(i)->value.at(j)) + "|d:" + std::to_string(p->op.sysc->at(i)->sinfo.get_deep(j)) + "|n:" + std::to_string(p->op.sysc->at(i)->sinfo.get_last(j)) + "]";
        if(j+1 < p->op.sysc->at(i)->value.size()) {
          if(p->op.sysc->at(i)->nargno.at(j+1) > p->op.sysc->at(i)->nargno.at(j)) log += ", ";
        }
      }
      log += ");";
      flog(static_cast<uint64_t>(core), log.c_str());
      log = "";
    }
    break;
    case SYSDEVPROC:
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
    case SOCKET:
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

auto print_program(prog_t *program) -> void {
  switch(program->inuse) {
    case SYSCALL:
    for(int i{0}; i < program->nops; i++) {
      std::cout << "------------------------------" << std::endl;
      for(uint64_t j{0}; j < program->op.sysc->at(i)->value.size(); j++) {
        std::cout << "value: " << program->op.sysc->at(i)->value.at(j) << "; deep: " << program->op.sysc->at(i)->sinfo.get_deep(j) << "; ndeep: ";
        for(uint64_t k{0}; k < program->op.sysc->at(i)->sinfo.get_deep(j); k++) std::cout << program->op.sysc->at(i)->sinfo.get(j, k) << ",";
        std::cout << std::endl;
      }
    }
    break;
    case SYSDEVPROC:
    for(int i{0}; i < program->nops; i++) {
      std::cout << "------------------------------" << std::endl;
      for(uint64_t j{0}; j < program->op.sdp->at(i)->value.size(); j++) {
        std::cout << "value: " << program->op.sdp->at(i)->value.at(j) << "; deep: " << program->op.sdp->at(i)->sinfo.get_deep(j) << "; ndeep: ";
        for(uint64_t k{0}; k < program->op.sdp->at(i)->sinfo.get_deep(j); k++) std::cout << program->op.sdp->at(i)->sinfo.get(j, k) << ",";
        std::cout << std::endl;
      }
    }
    break;
    case SOCKET:
    for(int i{0}; i < program->nops; i++) {
      std::cout << "------------------------------" << std::endl;
      for(uint64_t j{0}; j < program->op.sock->at(i)->value.size(); j++) {
        std::cout << "value: " << program->op.sock->at(i)->value.at(j) << "; deep: " << program->op.sock->at(i)->sinfo.get_deep(j) << "; ndeep: ";
        for(uint64_t k{0}; k < program->op.sock->at(i)->sinfo.get_deep(j); k++) std::cout << program->op.sock->at(i)->sinfo.get(j, k) << ",";
        std::cout << std::endl;
      }
    }
    break;
  }
}

auto execute_program(prog_t *program) -> pid_t {
  auto pid{fork()};

  switch(pid) {
    case 0:
    alarm(2);
    if(setsid() == -1) perror("setsid");

    for(auto i{0}; i < program->nops; i++) {
      switch(program->inuse) {
        case SYSCALL:
        execute(program->op.sysc->at(i));
        break;
        case SYSDEVPROC:
        execute(program->op.sdp->at(i));
        break;
        case SOCKET:
        execute(program->op.sock->at(i));
        break;
      }
    }

    delete program;

    exit(0);
    case -1:
    perror("fork");
    return -1;
    default:
    return pid;
  }
}

auto start(int32_t core, fuzzinfo_t fi) -> void {
  prog_t *program{nullptr};
  uint64_t ncovered{0}, prev_ncovered{0}, prev_addr_covered{0};

  while(1) {
    // generation

    if(fi.get_corpus_count() < 1) {
      for(int32_t i{0}; i < 0x10; i++) {
        auto rnd{get_random(0,2)};

        switch(rnd) {
          case SYSCALL:
          program = create_program1();
          break;
          case SYSDEVPROC:
          program = create_program2();
          break;
          case SOCKET:
          program = create_program3();
          break;
        }
        fi.add_corpus(program);
      }
    }

    // mutation
    for(int32_t i{0}; i < 0x10; i++) {
      program = fi.get_corpus();
      if(program == nullptr) break;

      flog_program(program, core);

      fi.record_coverage(core);
      waitpid(execute_program(program), NULL, 0);
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
      waitpid(execute_program(program), NULL, 0);
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

auto spawn_threads(void *unused) -> int {
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

auto main(int argc, char **argv) -> int32_t {
  void *stack{nullptr};
  std::fstream f1, f2, f3;
  pid_t pid{};
  std::string path;

  // prepare filenames for virtual device fuzzing operations

  path = "/dev";
  for(auto& entry : std::filesystem::directory_iterator(path))
    virtual_dev_names.push_back(entry.path());

  path = "/proc";
  for(auto& entry : std::filesystem::directory_iterator(path))
    virtual_dev_names.push_back(entry.path());

  path = "/sys/class";
  for(auto& entry : std::filesystem::recursive_directory_iterator(path))
    virtual_dev_names.push_back(entry.path());

  if(argc > 1) {
    if(std::stoi(argv[1]) == 1) {
        stack = mmap(NULL, PAGESIZE*4, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
        if(stack == (void *)-1) error("mmap");
        pid = clone(spawn_threads, stack+PAGESIZE*4, CLONE_NEWUSER|SIGCHLD, NULL);
        if(pid == -1) error("clone");

        f1.open("/proc/" + std::to_string(pid) + "/setgroups");
        f2.open("/proc/" + std::to_string(pid) + "/uid_map");
        f3.open("/proc/" + std::to_string(pid) + "/gid_map");

        f1.write("deny", 4);
        f2.write("0 1000 1", 8);
        f3.write("0 1000 1", 8);

        f1.close();
        f2.close();
        f3.close();

        std::string x;
        std::cin >> x;

        goto out;
    }
  }


  spawn_threads(NULL);

out:
  return 0;
}
