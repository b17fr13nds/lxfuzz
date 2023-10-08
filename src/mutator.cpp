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
  return;
}

auto remove_op(prog_t *p) -> void {
  switch(p->inuse) {
    case SYSCALL:
    if(p->op.sysc->size() > 1)
      p->op.sysc->pop_back();
    else goto out;
    break;
    case SYSDEVPROC:
    if(p->op.sdp->size() > 1)
      p->op.sdp->pop_back();
    else goto out;
    break;
    case SOCKET:
    if(p->op.sock->size() > 1)
      p->op.sock->pop_back();
    else goto out;
    break;
  }

  p->nops--;
out:
  return;
}

auto change_value(prog_t *p) -> void {
  auto idx{get_random(0, p->nops-1)};

  switch(p->inuse) {
    case SYSCALL:
    if(p->op.sysc->at(idx)->value.size())
      p->op.sysc->at(idx)->value.at(get_random(0,p->op.sysc->at(idx)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case SYSDEVPROC:
    if(p->op.sdp->at(idx)->value.size())
      p->op.sdp->at(idx)->value.at(get_random(0,p->op.sdp->at(idx)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
    case SOCKET:
    if(p->op.sock->at(idx)->value.size())
      p->op.sock->at(idx)->value.at(get_random(0,p->op.sock->at(idx)->value.size()-1)) = get_random(0,0xffffffffffffffff);
    break;
  }

  return;
}

auto insert_value(prog_t *p) -> void {
  auto idx{get_random(0, p->nops-1)};
  int insert_idx{};

  switch(p->inuse) {
    case SYSCALL:
    if(p->op.sysc->at(idx)->value.size()) {
      insert_idx = get_random(1,p->op.sysc->at(idx)->value.size());

      if(!p->op.sysc->at(idx)->sinfo.get_deep(insert_idx-1)) break;

      p->op.sysc->at(idx)->value.insert(p->op.sysc->at(idx)->value.begin() + insert_idx, get_random(0,0xffffffffffffffff));
      p->op.sysc->at(idx)->sinfo.structinfo.insert(p->op.sysc->at(idx)->sinfo.structinfo.begin() + insert_idx, p->op.sysc->at(idx)->sinfo.structinfo.at(insert_idx-1));
      p->op.sysc->at(idx)->nargno.insert(p->op.sysc->at(idx)->nargno.begin() + insert_idx, p->op.sysc->at(idx)->nargno.at(insert_idx-1));
    }
    break;
    case SYSDEVPROC:
    if(p->op.sdp->at(idx)->value.size()) {
      insert_idx = get_random(1,p->op.sdp->at(idx)->value.size());

      if(!p->op.sdp->at(idx)->sinfo.get_deep(insert_idx-1)) break;

      p->op.sdp->at(idx)->value.insert(p->op.sdp->at(idx)->value.begin() + insert_idx, get_random(0,0xffffffffffffffff));
      p->op.sdp->at(idx)->sinfo.structinfo.insert(p->op.sdp->at(idx)->sinfo.structinfo.begin() + insert_idx, p->op.sdp->at(idx)->sinfo.structinfo.at(insert_idx-1));
    }
    break;
    case SOCKET:
    if(p->op.sock->at(idx)->value.size()) {
      insert_idx = get_random(1,p->op.sock->at(idx)->value.size());

      if(!p->op.sock->at(idx)->sinfo.get_deep(insert_idx-1)) break;

      p->op.sock->at(idx)->value.insert(p->op.sock->at(idx)->value.begin() + insert_idx, get_random(0,0xffffffffffffffff));
      p->op.sock->at(idx)->sinfo.structinfo.insert(p->op.sock->at(idx)->sinfo.structinfo.begin() + insert_idx, p->op.sock->at(idx)->sinfo.structinfo.at(insert_idx-1));
    }
    break;
  }

  return;
}


auto mutate_prog(prog_t *p) -> void {
  switch(get_random(0,3)) {
    case 0:
    add_op(p);
    break;
    case 1:
    remove_op(p);
    break;
    case 2:
    change_value(p);
    break;
    case 3:
    insert_value(p);
    break;
  }

  return;
}
