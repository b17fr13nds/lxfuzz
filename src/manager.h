typedef struct {
  unsigned long total_execs;
  double execs_per_sec;
} stats_t;

inline void error(const char *str) {
  perror(str);
  exit(-1);
}

auto print_usage_and_exit(char **) -> void;
auto parse_cmdline(int) -> const char **;
auto start_instance(int) -> void;
auto check_if_alive(int) -> bool;
auto save_crash(int) -> void;
auto cleanup(int) -> void;
