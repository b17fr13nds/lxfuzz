#include <iostream>
#include "fuzzer.h"

// generic mutator, must be set up manually

auto mutate_prog(prog_t *p) -> void {
  auto tmp{get_random(0, program->op.nops-1)};
  switch(program->inuse) {
    case 0:
    program->op.sysc->at(tmp)->value.at(get_random(0,program->op.sysc->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case 1:
    program->op.sdp->at(tmp)->value.at(get_random(0,program->op.sdp->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case 2:
    program->op.sock->at(tmp)->value.at(get_random(0,program->op.sock->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
  }

  return;
}
