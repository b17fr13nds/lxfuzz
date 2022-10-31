#include "hypercall.h"

void flog(unsigned long thread_no, const void *arg) {
  __asm__(
    ".byte 0x0f;"
    ".byte 0xa6;"
  );
}
