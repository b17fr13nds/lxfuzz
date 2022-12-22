#include <iostream>
#include "fuzzer.h"

// generic mutator, must be set up manually

auto mutate_prog(prog_t *p) -> void {
  auto tmp{get_random(0, p->nops-1)};

  switch(p->inuse) {
    case 0:
    if(p->op.sysc->at(tmp)->value.size())
      p->op.sysc->at(tmp)->value.at(get_random(0,p->op.sysc->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case 1:
    if(p->op.sdp->at(tmp)->value.size())
      p->op.sdp->at(tmp)->value.at(get_random(0,p->op.sdp->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case 2:
    if(p->op.sock->at(tmp)->value.size())
      p->op.sock->at(tmp)->value.at(get_random(0,p->op.sock->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
  }

  return;
}
