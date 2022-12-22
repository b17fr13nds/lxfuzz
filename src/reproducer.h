#include "fuzzer.h"

#define PARSE_VALUES(op, stop) {\
std::vector<uint64_t> v;\
    do {\
        readuntil(f, "v:");\
        op->value.push_back(std::stoul(readuntil(f, "|")));\
        readuntil(f, "d:");\
        op->sinfo.push(v);\
\
        int d = std::stoi(readuntil(f, "|"));\
\
        for(int i{0}; i < d+1; i++) {\
            op->sinfo.push_end(d);\
        }\
        readuntil(f, "]");\
    } while(static_cast<char>(f.peek()) != stop);\
}

auto readuntil(std::ifstream&, std::string) -> std::string;
auto readuntil(std::ifstream&, std::string, std::string) -> std::string;
auto parse_syscall(std::ifstream&) -> prog_t*;
auto parse_socket(std::ifstream&) -> prog_t*;
auto parse_sysdevproc(std::ifstream&) -> prog_t*;
auto parse_next(std::ifstream&) -> prog_t*;
auto execute_program(prog_t*) -> void;
auto start(uint32_t) -> void;
auto main() -> int32_t;
