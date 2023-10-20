#include "fuzzer.h"

#define PARSE_VALUES_SYSCALL(op, stop) {\
    int32_t cnt{1};\
    std::vector<uint64_t> v;\
    readuntil(f, "[");\
    do {\
        if(readuntil(f, "v:").find(",") != std::string::npos) cnt++;\
        op->value.push_back(std::stoul(readuntil(f, "|")));\
        readuntil(f, "d:");\
        op->sinfo.push(v);\
\
        int d = std::stoi(readuntil(f, "|"));\
        readuntil(f, "n:");\
        int n = std::stoi(readuntil(f, "]"));\
\
        for(int i{0}; i < d; i++) {\
            op->sinfo.push_end(0);\
        }\
\
        op->sinfo.push_end(n);\
        op->nargno.push_back(cnt);\
\
    } while(static_cast<char>(f.peek()) != stop);\
    op->size = cnt;\
}

#define PARSE_VALUES(op, stop) {\
    std::vector<uint64_t> v;\
    do {\
        readuntil(f, "v:");\
        op->value.push_back(std::stoul(readuntil(f, "|")));\
        readuntil(f, "d:");\
        op->sinfo.push(v);\
\
        int d = std::stoi(readuntil(f, "|"));\
        readuntil(f, "n:");\
        int n = std::stoi(readuntil(f, "]"));\
\
        for(int i{0}; i < d; i++) {\
            op->sinfo.push_end(1);\
        }\
        op->sinfo.push_end(n);\
    } while(static_cast<char>(f.peek()) != stop);\
}

auto readuntil(std::ifstream&, std::string) -> std::string;
auto readuntil(std::ifstream&, std::string, std::string) -> std::string;
auto parse_syscall(std::ifstream&) -> prog_t*;
auto parse_socket(std::ifstream&) -> prog_t*;
auto parse_sysdevproc(std::ifstream&) -> prog_t*;
auto parse_next(std::ifstream&) -> prog_t*;
auto execute_program(prog_t*) -> pid_t;
auto start(uint32_t) -> void;
auto main(int, char **) -> int32_t;
