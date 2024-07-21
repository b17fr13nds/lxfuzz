#include <vector>
#include <string>

class parse_args {
  std::vector<std::string> *args;

public:
  parse_args(int32_t argc, char **argv) {
    args = new std::vector<std::string>(argv, argv+argc);
  }

  auto get_opt(std::string opt) -> std::string {
    for(uint64_t i{0}; i < args->size()-1; i++) {
      std::string &e = args->at(i);
      if(("-" + opt) == e || ("--" + opt) == e) return args->at(i+1);
    }

    return "";
  }

  auto check_opt_exist(std::string opt) -> bool {
    for(uint64_t i{0}; i < args->size(); i++) {
      std::string &e = args->at(i);
      if(("-" + opt) == e || ("--" + opt) == e) return true;
    }

    return false;
  }
};