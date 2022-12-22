typedef struct {
  uint64_t total_execs;
  double execs_per_sec;
  uint64_t corpus_count;
} stats_t;

inline void error(const char *str) {
  perror(str);
  exit(-1);
}

auto print_usage_and_exit(char **) -> void;
auto parse_cmdline(int32_t) -> const char **;
auto start_instance(int32_t) -> void;
auto check_if_alive(int32_t) -> bool;
auto save_crash(int32_t) -> void;
auto cleanup(int32_t) -> void;
