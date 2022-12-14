#include <iostream>
#include <thread>
#include <string>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "reproducer.h"

auto readuntil(std::ifstream &f, std::string what) -> std::string {
  std::string ret;

  do {
    ret += f.get();
  } while(ret.find(what) == std::string::npos);

  return ret;
}

auto readuntil(std::ifstream &f, std::string what1, std::string what2) -> std::string {
  std::string ret;

  do {
    ret += f.get();
  } while(ret.find(what1) == std::string::npos && ret.find(what2) == std::string::npos);

  return ret;
}

auto parse_syscall(std::ifstream &f) -> prog_t* {
  prog_t *ret = new prog_t;
  syscall_t *sysc;
  std::string tmp;
  uint64_t saved{0};

  ret->inuse = 0;
  ret->op.sysc = new std::vector<syscall_t*>;

  do {
    ret->nops++;
    sysc = new syscall_t;

    readuntil(f, "(");
    sysc->sysno = std::stoi(readuntil(f, ",", ")"));

    if(f.get() == ';') goto out;

    PARSE_VALUES(sysc, ')');

    for(uint64_t i{0}; i < sysc->sinfo.get_size(); i++) {
      switch(sysc->sinfo.get_deep(i)) {
        case 0:
        saved = 0;
        sysc->nargs++;
        break;
        case 1:
        if(sysc->sinfo.get_last(i) == saved) break;
        saved = sysc->sinfo.get_last(i);
        sysc->nargs++;
        break;
        default:
        if(i > 1) {
          if(sysc->sinfo.get_deep(i-1) != 0) break;
        } else break;
        sysc->nargs++;
        break;
      }
    }

out:
    getline(f, tmp, '\n'); f.get();
    ret->op.sysc->push_back(sysc);
  } while(f.peek() != '-' && !f.eof());

  return ret;
}

auto parse_sysdevproc(std::ifstream &f) -> prog_t* {
  prog_t *ret = new prog_t;
  sysdevproc_op_t *sdpop;
  std::string tmp;
  int fd{};

  ret->inuse = 1;
  ret->op.sdp = new std::vector<sysdevproc_op_t*>;

  readuntil(f, "(\"");
  ret->devname = readuntil(f, "\"");
  ret->devname.pop_back();

  readuntil(f, ", ");
  ret->prot = std::stoi(readuntil(f, ")"));

  fd = open(ret->devname.c_str(), ret->prot);

  do {
    ret->nops++;
    sdpop = new sysdevproc_op_t;
    sdpop->fd = fd;
    tmp = readuntil(f, "(");

    if(tmp == "ioctl(") {
      sdpop->option = 0;

      readuntil(f, "fd, 0, ");
      PARSE_VALUES(sdpop, ')');
    } else if(tmp == "read(") {
      sdpop->option = 1;

      readuntil(f, "fd, ");
      PARSE_VALUES(sdpop, ',');

      readuntil(f, ", ");
      sdpop->size = std::stoi(readuntil(f, ")"));
    } else {
      sdpop->option = 2;

      readuntil(f, "fd, ");
      PARSE_VALUES(sdpop, ',');

      readuntil(f, ", ");
      sdpop->size = std::stoi(readuntil(f, ")"));
    }

    getline(f, tmp, '\n'); f.get();
    ret->op.sdp->push_back(sdpop);
  } while(f.peek() != '-' && !f.eof());

  return ret;
}

auto parse_socket(std::ifstream &f) -> prog_t* {
  prog_t *ret = new prog_t;
  socket_op_t *sop;
  std::string tmp;
  int fd{};

  ret->inuse = 2;
  ret->op.sock = new std::vector<socket_op_t*>;

  readuntil(f, "(");
  ret->domain = std::stoi(readuntil(f, ","));
  ret->type = std::stoi(readuntil(f, ","));
  fd = socket(ret->domain, ret->type, 0);

  do {
    ret->nops++;
    sop = new socket_op_t;
    sop->fd = fd;
    tmp = readuntil(f, "(");

    if(tmp == "setsockopt(") {
      sop->option = 0;

      readuntil(f, "fd, SOL_SOCKET, ");
      PARSE_VALUES(sop, ',');

      readuntil(f, " ");
      sop->size = std::stoi(readuntil(f, ")"));
    } else if(tmp == "write(") {
      sop->option = 1;

      readuntil(f, "fd, ");
      PARSE_VALUES(sop, ',');

      readuntil(f, ", ");
      sop->size = std::stoi(readuntil(f, ")"));

    } else if(tmp == "sendmsg(") {
      sop->option = 2;

      readuntil(f, "fd, {.iov.iov_base = ");
      PARSE_VALUES(sop, ',');

      readuntil(f, " .iov.len = ");
      sop->size = std::stoi(readuntil(f, ")"));

    } else {
      sop->option = 3;

      readuntil(f, "fd, 0, ");
      PARSE_VALUES(sop, ')');
    }

    getline(f, tmp, '\n'); f.get();
    ret->op.sock->push_back(sop);
  } while(f.peek() != '-' && !f.eof());

  return ret;
}

auto parse_next(std::ifstream &f) -> prog_t * {
  prog_t *ret;
  std::string tmp;

  tmp = readuntil(f, ")");

  if(tmp == "(syscall)") {
    ret = parse_syscall(f);
  } else if(tmp == "(sysdevproc)") {
    ret = parse_sysdevproc(f);
  } else {
    ret = parse_socket(f);
  }

  getline(f, tmp, '\n'); f.get();

  return ret;
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

auto start(uint32_t core) -> void {
  prog_t *program{nullptr};
  std::string tmp;
  std::ifstream f;

retry:
  f.open("log_t" + std::to_string(core));

  while(!f.eof()) {
    readuntil(f, "NEW PROGRAM ");
    program = parse_next(f);
    execute_program(program);
    delete program;
  }

  f.close();

  goto retry;
}

auto main() -> int32_t {
  auto cores_available = std::thread::hardware_concurrency();
  std::thread *t = new std::thread[cores_available];

  std::filesystem::current_path("./crash");

  for(decltype(cores_available) i{0}; i < cores_available; i++) {
      t[i] = std::thread(start, i);
  }

  std::string x;
  std::cin >> x;

  return 0;
}

