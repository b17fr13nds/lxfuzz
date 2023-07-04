inline void error(const char *str) {
  perror(str);
  exit(-1);
}

auto print_usage_and_exit(char **) -> void;
auto parse_cmdline(int32_t) -> const char **;
auto start_instance(std::string) -> void;
auto check_if_alive(int32_t) -> bool;
auto parse_fuzzer_args(char **) -> std::string;