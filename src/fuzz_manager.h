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

inline void error(const char *str) {
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
