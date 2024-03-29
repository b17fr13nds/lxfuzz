#include <vector>
#include <variant>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (64<<10)

#define KCOV_TRACE_PC 0
#define KCOV_TRACE_CMP 1

#define PAGESIZE 0x1000

inline auto error(const char *str) -> void {
  perror(str);
  exit(-1);
}

auto get_random(uint64_t, uint64_t) -> uint64_t;

enum program_type {SYSCALL, SYSDEVPROC, SOCKET};

class structinfo_t {
public:
  std::vector<std::vector<uint64_t>> structinfo;

  auto get_size() -> uint64_t {
    return structinfo.size();
  }

  auto get_deep(uint64_t n) -> uint64_t {
    return structinfo.at(n).size()-1;
  }

  auto get(uint64_t a, uint64_t b) -> uint64_t {
    return structinfo.at(a).at(b);
  }

  auto push(std::vector<uint64_t> vec) -> void {
    structinfo.push_back(vec);
  }

  auto push_end(uint64_t val) -> void {
    structinfo.back().push_back(val);
  }

  auto incr_end(uint64_t pos) -> void {
    structinfo.back().at(pos)++;
  }

  auto get_last(uint64_t n) -> uint64_t {
    return structinfo.at(n).back();
  }

  auto get_vec(uint64_t pos) -> std::vector<uint64_t> {
    return structinfo.at(pos);
  }
};

class base_op_t {
public:
  base_op_t() : size{0} {};

  uint16_t size; // number of qwords at base level
  std::vector<uint64_t> value;
  structinfo_t sinfo;
};

class syscall_op_t : public base_op_t {
public:
  syscall_op_t() : sysno{0} {};

  uint16_t sysno;
  std::vector<uint32_t> nargno;
};

class sysdevproc_op_t : public base_op_t {
public:
  sysdevproc_op_t() : option{0}, request{0} {};

  uint8_t option;
  uint64_t request;
};

class socket_op_t : public base_op_t {
public:
  socket_op_t() : option{0}, request{0}, optname{0} {};

  uint8_t option;
  uint64_t request;
  int32_t optname;
};

class prog_t {
public:
  prog_t() : nops{0} {};
  ~prog_t() {
    switch(inuse) {
      case SYSCALL:
      for(uint64_t i{0}; i < op.sysc->size(); i++) {
        delete op.sysc->at(i);
      }
      delete op.sysc;
      break;
      case SYSDEVPROC:
      for(uint64_t i{0}; i < op.sdp->size(); i++) {
        delete op.sdp->at(i);
      }
      close(fd);
      delete op.sdp;
      break;
      case SOCKET:
      for(uint64_t i{0}; i < op.sock->size(); i++) {
        delete op.sock->at(i);
      }
      close(fd);
      delete op.sock;
      break;
    }
  }

  auto get_value(int32_t idx) -> std::vector<uint64_t>* {
    switch(inuse) {
      case SYSCALL:
      return &op.sysc->at(idx)->value;
      case SYSDEVPROC:
      return &op.sdp->at(idx)->value;
      case SOCKET:
      return &op.sock->at(idx)->value;
      default:
      return nullptr;
    }
  }

  auto get_sinfo(int32_t idx) -> structinfo_t* {
    switch(inuse) {
      case SYSCALL:
      return &op.sysc->at(idx)->sinfo;
      case SYSDEVPROC:
      return &op.sdp->at(idx)->sinfo;
      case SOCKET:
      return &op.sock->at(idx)->sinfo;
      default:
      return nullptr;
    }
  }

  uint32_t nops;
  uint32_t inuse;
  union {
    std::vector<syscall_op_t*> *sysc;
    std::vector<sysdevproc_op_t*> *sdp;
    std::vector<socket_op_t*> *sock;
  } op;

  std::string log;

  // sockfd or devfd
  int32_t fd;

  // devices
  std::string devname;
  int32_t prot;

  // sockets
  int32_t domain;
  int32_t type;
};

typedef struct {
  int32_t kcov_fd;
  uint64_t *addr_covered, ncovered;
} kcov_data_t;

class fuzzinfo_t {
  std::vector<prog_t*> corpus;
  kcov_data_t **kcov;
public:
  fuzzinfo_t(int32_t n) : kcov{nullptr} {
    kcov = new kcov_data_t*[n];

    for(auto i{0}; i < n; i++) {
      kcov[i] = new kcov_data_t;
      kcov[i]->kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
      if(ioctl(kcov[i]->kcov_fd, KCOV_INIT_TRACE, COVER_SIZE) == -1) error("ioctl");
      kcov[i]->addr_covered = (uint64_t*)mmap(NULL, COVER_SIZE*sizeof(uint64_t), PROT_READ|PROT_WRITE, MAP_SHARED, kcov[i]->kcov_fd, 0);
    }
  }

  virtual void record_coverage(int32_t thread) {
    if(ioctl(kcov[thread]->kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC) == -1) error("ioctl");
    __atomic_store_n(&kcov[thread]->addr_covered[0], 0, __ATOMIC_RELAXED);
  }

  virtual uint64_t stop_recording(int32_t thread) {
    kcov[thread]->ncovered = __atomic_load_n(&kcov[thread]->addr_covered[0], __ATOMIC_RELAXED);
    if(ioctl(kcov[thread]->kcov_fd, KCOV_DISABLE, 0) == -1) error("ioctl");

    return kcov[thread]->ncovered;
  }

  virtual uint64_t get_address(int32_t thread, uint64_t idx) {
    return kcov[thread]->addr_covered[idx];
  }

  virtual void add_corpus(prog_t *p) {
    corpus.push_back(p);
  }

  virtual prog_t *get_corpus() {
    prog_t *tmp;

    if(!corpus.size()) {
      tmp = nullptr;
    } else {
      tmp = corpus.back();
      corpus.pop_back();
    }
    return tmp;
  }

  virtual uint64_t get_corpus_count() {
    return corpus.size();
  }
};

#define SETVAL(x, y) {\
  deref(x, &offsets)[perstruct_cnt.back()] = y.at(i);\
  perstruct_cnt.back()++;\
}

#define REALLOC_STRUCT(x) {\
  {\
    size_t tmp{offsets.back()};\
    offsets.pop_back();\
    size.back() += 8;\
    deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-2)-1] = reinterpret_cast<uint64_t>(realloc(reinterpret_cast<void*>(deref(x, &offsets)[perstruct_cnt.at(perstruct_cnt.size()-2)-1]),size.back()));\
    offsets.push_back(tmp);\
  }\
}

#define ALLOC_STRUCT(x) {\
  {\
    deref(x, &offsets)[perstruct_cnt.back()] = reinterpret_cast<uint64_t>(malloc(8));\
    offsets.push_back(perstruct_cnt.back());\
    perstruct_cnt.back()++;\
    perstruct_cnt.push_back(0);\
    size.push_back(8);\
  }\
}

template <typename T>
inline auto check_smaller_before(uint64_t start, uint64_t c, T* s) -> bool {
  for(int64_t i{static_cast<int64_t>(start)+1}; i >= 0; i--) {
    if(s->sinfo.get_deep(i) >= c) break;
    if(s->sinfo.get_deep(i) < c) return true;
  }

  return false;
}

inline auto deref(uint64_t *in, std::vector<size_t>* offsets) -> uint64_t* {
  uint64_t *tmp{in};

  for(uint64_t i{0}; i < offsets->size(); i++) {
    tmp = reinterpret_cast<uint64_t*>(tmp[offsets->at(i)]);
  }

  return tmp;
}

template <typename T>
inline auto create_data(T *op, int32_t qwords) -> void {
  int32_t cnt{0}, max_struct_rand{1}, curr_rand{0}, repititions{1};
  uint64_t saved{0}, structure_deep{0};
  std::vector<uint64_t> tmp;

  while(cnt < qwords) {
    curr_rand = get_random(0,max_struct_rand);
    structure_deep = static_cast<uint64_t>(curr_rand);

    if(structure_deep && get_random(0,2))
      repititions = get_random(5,20);
    else
      repititions = 1;

    for(int32_t k{0}; k < repititions; k++) {
      op->value.push_back(get_random(0,0xffffffffffffffff));
      if(curr_rand == max_struct_rand) {
        max_struct_rand++;
      } else if(max_struct_rand > 1) {
        max_struct_rand--;
      }

      op->sinfo.push(tmp);
      op->sinfo.push_end(1);
      for(uint64_t j{0}; j < structure_deep; j++) {
        op->sinfo.push_end(1);

        for(uint64_t i{0}; i < op->sinfo.get_size()-1; i++) {
          if(j+1 <= op->sinfo.get_deep(i) && op->sinfo.get_deep(i)) {
            if(check_smaller_before<T>(i, j+1, op)) op->sinfo.incr_end(j+1);
          }
        }
      }

      switch(op->sinfo.get_deep(op->sinfo.get_size()-1)) {
        case 0:
        if constexpr(std::is_same_v<T, syscall_op_t>) {
          if(saved > 0) {
            op->nargno.at(op->nargno.size()-1) = cnt;
          }
        }
        saved = 0;
        cnt++;
        break;
        case 1:
        if(op->sinfo.get_size() > 1) {
          if(op->sinfo.get_last(op->sinfo.structinfo.size()-1) == saved) break;
        }
        saved = op->sinfo.get_last(op->sinfo.structinfo.size()-1);
        cnt++;
        break;
        default:
        if(op->sinfo.get_size()-1 > 1) {
          if(op->sinfo.get_deep(op->sinfo.get_size()-2) != 0) break;
        } else break;
        cnt++;
        break;
      }

      if constexpr(std::is_same_v<T, syscall_op_t>) {
        op->nargno.push_back(cnt);
      }
    }
  }

  op->size = qwords;
  return;
}

template <typename T>
inline auto parse_data(T *op) -> uint64_t * {
  uint64_t *args = new uint64_t[op->size+2];

  std::vector<size_t> size;
  std::vector<size_t> offsets;
  std::vector<size_t> perstruct_cnt;

  perstruct_cnt.push_back(0);

  for(uint64_t i{0}; i < op->value.size(); i++) {
    // value not in a structure
    if(!op->sinfo.get_deep(i)) {

      if(i && op->sinfo.get_deep(i) < op->sinfo.get_deep(i-1)) {
        for(uint64_t j{0}; j < op->sinfo.get_deep(i-1) - op->sinfo.get_deep(i); j++) {
          if(!size.size()) break;
          size.pop_back();
          offsets.pop_back();
          perstruct_cnt.pop_back();
        }
      }
      SETVAL(args, op->value);

    // value in deeper structure than before
    } else if(i && op->sinfo.get_deep(i) > op->sinfo.get_deep(i-1)) {

      if(op->sinfo.get_deep(i-1)) {
        REALLOC_STRUCT(args);
      }
      for(uint64_t j{0}; j < op->sinfo.get_deep(i) - op->sinfo.get_deep(i-1); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, op->value);

    // value in same structure depth than before
    } else if(i && op->sinfo.get_deep(i) == op->sinfo.get_deep(i-1)) {

      REALLOC_STRUCT(args);
      SETVAL(args, op->value);

    // value in less deep structure than before
    } else if(i && op->sinfo.get_deep(i) < op->sinfo.get_deep(i-1)) {

      for(uint64_t j{0}; j < op->sinfo.get_deep(i-1) - op->sinfo.get_deep(i); j++) {
        if(size.size() == 1) break;
        size.pop_back();
        offsets.pop_back();
        perstruct_cnt.pop_back();
      }

      // value in same structure than values before i-1
      if(op->sinfo.get(i, op->sinfo.get_deep(i)) == op->sinfo.get(i-1, op->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        SETVAL(args, op->value);

      // value in same structure depth than values before i-1, but new struct
      } else if(op->sinfo.get(i, op->sinfo.get_deep(i)) > op->sinfo.get(i-1, op->sinfo.get_deep(i))) {

        REALLOC_STRUCT(args);
        for(uint64_t j{0}; j < op->sinfo.get_deep(i) - op->sinfo.get_deep(i-1); j++) {
          ALLOC_STRUCT(args);
        }
        SETVAL(args, op->value);

      }
    
    // handle other scenarios
    } else if(op->sinfo.get_deep(i)) {

      for(uint64_t j{0}; j < op->sinfo.get_deep(i); j++) {
        ALLOC_STRUCT(args);
      }
      SETVAL(args, op->value);

    }
  }

  return args;
}

extern std::vector<std::string> virtual_dev_names;

auto flog_program(prog_t *, int32_t) -> void;
auto execute_program(prog_t*) -> pid_t;
auto print_program(prog_t *) -> void;

auto mutate_prog(prog_t *p) -> void;

template <typename... T>
auto exec_syscall(uint16_t, T...) -> void;
auto exec_syscall(uint16_t) -> void;
auto execute_syscallop(prog_t*) -> void;
auto create_syscallop() -> syscall_op_t*;
auto create_program1() -> prog_t*;

auto open_device(prog_t*) -> int32_t;
auto execute_sysdevprocop(prog_t*) -> void;
auto create_sysdevprocop() -> sysdevproc_op_t*;
auto create_program2() -> prog_t*;

auto open_socket(prog_t*) -> int32_t;
auto execute_socketop(prog_t*) -> void;
auto create_socketop() -> socket_op_t*;
auto create_program3() -> prog_t*;
