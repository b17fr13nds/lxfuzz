#include <iostream>
#include "fuzzer.h"

auto add_op(prog_t *p) -> void {
  switch(p->inuse) {
    case SYSCALL:
    p->op.sysc->push_back(create_syscall());
    break;
    case SYSDEVPROC:
    p->op.sdp->push_back(create_sysdevprocop());
    break;
    case SOCKET:
    p->op.sock->push_back(create_socketop());
    break;
  }

  p->nops++;
}

auto remove_op(prog_t *p) -> void {
  switch(p->inuse) {
    case SYSCALL:
    if(p->op.sysc->size())
      p->op.sysc->pop_back();
    break;
    case SYSDEVPROC:
    if(p->op.sdp->size())
      p->op.sdp->pop_back();
    break;
    case SOCKET:
    if(p->op.sock->size())
      p->op.sock->pop_back();
    break;
  }

  p->nops--;
}

auto change_value(prog_t *p) -> void {
  auto tmp{get_random(0, p->nops-1)};

  switch(p->inuse) {
    case SYSCALL:
    if(p->op.sysc->at(tmp)->value.size())
      p->op.sysc->at(tmp)->value.at(get_random(0,p->op.sysc->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case SYSDEVPROC:
    if(p->op.sdp->at(tmp)->value.size())
      p->op.sdp->at(tmp)->value.at(get_random(0,p->op.sdp->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case SOCKET:
    if(p->op.sock->at(tmp)->value.size())
      p->op.sock->at(tmp)->value.at(get_random(0,p->op.sock->at(tmp)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
  }
}

auto mutate_prog(prog_t *p) -> void {
  switch(get_random(0,2)) {
    case 0:
    add_op(p);
    break;
    case 1:
    remove_op(p);
    break;
    case 2:
    change_value(p);
    break;
  }

  return;
}
