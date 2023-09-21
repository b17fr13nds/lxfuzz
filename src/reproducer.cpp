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
    if(f.eof()) return "";
    ret += f.get();
  } while(ret.find(what) == std::string::npos);

  return ret;
}

auto readuntil(std::ifstream &f, std::string what1, std::string what2) -> std::string {
  std::string ret;

  do {
    if(f.eof()) return "";
    ret += f.get();
  } while(ret.find(what1) == std::string::npos && ret.find(what2) == std::string::npos);

  return ret;
}

auto parse_syscall(std::ifstream &f) -> prog_t* {
  prog_t *ret = new prog_t;
  syscall_op_t *sysc;
  std::string tmp;

  ret->inuse = 0;
  ret->op.sysc = new std::vector<syscall_op_t*>;

  do {
    ret->nops++;
    sysc = new syscall_op_t;

    readuntil(f, "(");
    sysc->sysno = std::stoi(readuntil(f, ",", ")"));

    if(f.get() == ';') goto out;

    PARSE_VALUES_SYSCALL(sysc, ')');

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

  getline(f, tmp, '\n'); f.get();

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

      readuntil(f, " ");
      sdpop->size = std::stoi(readuntil(f, ")"));
    } else {
      sdpop->option = 2;

      readuntil(f, "fd, ");
      PARSE_VALUES(sdpop, ',');

      readuntil(f, " ");
      tmp = readuntil(f, ")");
      sdpop->size = std::stoi(tmp);
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

  getline(f, tmp, '\n'); f.get();

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

      readuntil(f, " ");
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
  } else if(tmp == "(socket)") {
    ret = parse_socket(f);
  } else{
    return NULL;
  }

  getline(f, tmp, '\n'); f.get();

  return ret;
}


auto execute_program(prog_t *program) -> pid_t {
  auto pid{fork()};

  switch(pid) {
    case 0:
    alarm(2);
    if(setsid() == -1) perror("setsid");

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

    delete program;

    exit(0);
    case -1:
    perror("fork");
    return -1;
    default:
    return pid;
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
    if((program = parse_next(f)) == NULL) continue;
    waitpid(execute_program(program), NULL, 0);
    delete program;
  }

  f.close();

  goto retry;
}

auto spawn_threads(void *unused) -> int {
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

auto main(int argc, char **argv) -> int32_t {
  void *stack{nullptr};
  std::fstream f1, f2, f3;
  pid_t pid{};

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
