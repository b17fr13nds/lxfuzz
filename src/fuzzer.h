#include <vector>
#include <variant>
#include "manager.h"

class structinfo_t {
  std::vector<std::vector<unsigned long>> structinfo;
public:

  auto get_size() -> unsigned long {
    return structinfo.size();
  }

  auto get_deep(unsigned long n) -> unsigned long {
    return structinfo.at(n).size()-1;
  }

  auto get(unsigned long a, unsigned long b) -> unsigned long {
    return structinfo.at(a).at(b);
  }

  auto push(std::vector<unsigned long> vec) -> void {
    structinfo.push_back(vec);
  }

  auto push_end(unsigned long val) -> void {
    structinfo.at(get_size()-1).push_back(val);
  }

  auto incr_end(unsigned long pos) -> void {
    structinfo.at(get_size()-1).at(pos)++;
  }

  auto get_last() -> unsigned long {
    return structinfo.at(structinfo.size()-1).at(structinfo.at(structinfo.size()-1).size()-1);
  }

  auto get_vec(unsigned long pos) -> std::vector<unsigned long> {
    return structinfo.at(pos);
  }
};

class syscall_t {
public:
  syscall_t() : sysno{0}, nargs{0} {};

  unsigned short sysno;
  unsigned short nargs;
  std::vector<unsigned long> value;
  structinfo_t sinfo;

  std::string log;
};

class sysdevproc_op_t {
public:
  sysdevproc_op_t() : fd{0}, option{0}, request{0}, size{0} {};

  int fd;
  unsigned char option;
  unsigned long request;
  std::vector<unsigned long> value;
  structinfo_t sinfo;
  unsigned long size;

  std::string log;
};

class socket_op_t {
public:
  socket_op_t() : fd{0}, option{0}, request{0}, size{0}, optname{0} {};

  int fd;
  unsigned char option;
  unsigned long request;
  std::vector<unsigned long> value;
  structinfo_t sinfo;
  unsigned long size;
  int optname;

  std::string log;
};

typedef struct {
  unsigned char nops;
  int inuse;
  union {
    std::vector<syscall_t*> *sysc;
    std::vector<sysdevproc_op_t*> *sdp;
    std::vector<socket_op_t*> *sock;
  } op;
  std::string init_log;
} prog_t;

class fuzzinfo_t {
  std::vector<prog_t*> corpus;
  size_t corpus_cnt;
public:
  stats_t stats;

  virtual void add_corpus(prog_t *p) {
    corpus.push_back(p);
    corpus_cnt++;
  }
};

#define SETVAL(x, y) {\
  deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-1)] = y.at(i);\
  perstruct_cnt.at(perstruct_cnt.size()-1)++;\
}

#define REALLOC_STRUCT(x) {\
  tmp = offsets.back();\
  offsets.pop_back();\
  size.at(size.size()-1) += 8;\
  deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-2)-1] = reinterpret_cast<unsigned long>(realloc(reinterpret_cast<void*>(deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-2)-1]),size.at(size.size()-1)));\
  offsets.push_back(tmp);\
}

#define ALLOC_STRUCT(x) {\
  deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-1)] = reinterpret_cast<unsigned long>(malloc(8));\
  offsets.push_back(perstruct_cnt.at(perstruct_cnt.size()-1));\
  perstruct_cnt.at(perstruct_cnt.size()-1)++;\
  perstruct_cnt.push_back(0);\
  size.push_back(8);\
}

template <typename T>
inline auto check_smaller_before(unsigned long start, unsigned long c, T* s) -> bool {
  for(long i{static_cast<long>(start)+1}; i >= 0; i--) {
    if(s->sinfo.get_deep(i) >= c) break;
    if(s->sinfo.get_deep(i) < c) return true;
  }

  return false;
}

inline auto deref(unsigned long *in, std::vector<size_t>* offsets) -> unsigned long* {
  unsigned long *tmp{in};

  for(unsigned long i{0}; i < offsets->size(); i++) {
    tmp = reinterpret_cast<unsigned long*>(tmp[offsets->at(i)]);
  }

  return tmp;
}

auto get_random(unsigned long, unsigned long) -> unsigned long;
auto execute_program(prog_t*) -> void;
auto start(int) -> void;

template <typename... T>
auto exec_syscall(unsigned short, T...) -> void;
auto exec_syscall(unsigned short) -> void;
auto execute(syscall_t*) -> void;
auto create_syscall() -> syscall_t*;
auto create_program1() -> prog_t*;

auto open_device(prog_t*) -> int;
auto execute(sysdevproc_op_t*) -> void;
auto create_sysdevprocop() -> sysdevproc_op_t*;
auto create_program2() -> prog_t*;

auto open_socket(prog_t*) -> int;
auto execute(socket_op_t*) -> void;
auto create_socketop() -> socket_op_t*;
auto create_program3() -> prog_t*;
