#include "hypercall.h"

void flog(uint64_t thread_no, const void *arg) {
  __asm__(
    ".byte 0x0f;"
    ".byte 0xa6;"
  );
}

void fstats(uint64_t corpus_count) {
  __asm__(
    ".byte 0x0f;"
    ".byte 0xa7;"
  );
}
