#include <sstream>
#include <curses.h>

class screen_buffer {
public:
  std::stringstream ss;

  template <typename T>
  auto operator<<(T data) {
    ss << data;
    return std::move(*this);
  }

  void print(int x, int y) {
    mvwaddstr(stdscr, y, x, ss.str().c_str());
    refresh();
    ss.str(std::string());
  } 
};

inline auto rectangle(int x1, int y1, int x2, int y2) -> void {
    mvhline(y1, x1, 0, x2-x1);
    mvhline(y2, x1, 0, x2-x1);
    mvvline(y1, x1, 0, y2-y1);
    mvvline(y1, x2, 0, y2-y1);
    mvaddch(y1, x1, ACS_ULCORNER);
    mvaddch(y2, x1, ACS_LLCORNER);
    mvaddch(y1, x2, ACS_URCORNER);
    mvaddch(y2, x2, ACS_LRCORNER);
}

inline auto update_boxes() -> void {
  rectangle(4,5,39,11);
  rectangle(40,5,75,11);
  rectangle(0,1,79,23);
  refresh();
}

typedef struct {
  uint64_t total_execs;
  double execs_per_sec;
  uint64_t corpus_count;
} stats_t;

typedef struct {
  int32_t fd;
  int32_t pid;
  int32_t crashes;
  uint64_t* logsizes;
} instance_t;

inline auto error(const char *str) -> void {
  perror(str);
  exit(-1);
}

auto print_usage_and_exit(char **) -> void;
auto parse_cmdline(int32_t) -> const char **;
auto prepare_instance(int32_t) -> void;
auto start_instance(int32_t, std::string) -> void;
auto stop_instance(int32_t) -> void;
auto check_if_alive(int32_t) -> bool;
auto save_crash(int32_t) -> void;
auto cleanup(int32_t) -> void;
auto parse_fuzzer_args(char **) -> std::string;
