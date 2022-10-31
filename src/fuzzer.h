#include <vector>
#include <variant>

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
  unsigned short sysno;
  unsigned short nargs;
  std::vector<unsigned long> value;
  structinfo_t sinfo;
  std::string log;
};

class sysdevproc_op_t {
public:
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

typedef struct {
  unsigned long total_execs;
  double execs_per_sec;
} stats_t;

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

inline void error(const char *str) {
  perror(str);
  exit(-1);
}

auto deref(unsigned long *, std::vector<size_t>*) -> unsigned long*;
template <typename... T>
auto exec_syscall(unsigned short, T...);
auto exec_syscall(unsigned short);
auto open_device(prog_t *) -> int;
auto open_socket(prog_t *) -> int;
auto execute(syscall_t*) -> void;
auto execute(sysdevproc_op_t*) -> void;
auto execute(socket_op_t*) -> void;
auto execute_program(prog_t *) -> void;
auto get_random(unsigned long, unsigned long) -> unsigned long;
auto check_smaller_before(unsigned long, unsigned long, syscall_t*) -> bool;
auto check_smaller_before(unsigned long, unsigned long, sysdevproc_op_t*) -> bool;
auto check_smaller_before(unsigned long, unsigned long, socket_op_t*) -> bool;
auto create_program1() -> prog_t*;
auto create_program2() -> prog_t*;
auto create_program3() -> prog_t*;
