#include <iostream>
#include "fuzzer.h"

auto add_op(prog_t *p) -> void {
  switch(p->inuse) {
    case SYSCALL:
    p->op.sysc->push_back(create_syscallop());
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

  if(p->get_value(idx)->size())
    p->get_value(idx)->at(get_random(0,p->get_value(idx)->size()-1)) = get_random(0,0xffffffffffffffff);

  return;
}

auto insert_value(prog_t *p) -> void {
  auto idx{get_random(0, p->nops-1)};
  int32_t insert_idx{};

  if(p->get_value(idx)->size()) {
    insert_idx = get_random(1,p->get_value(idx)->size());

    if(!p->get_sinfo(idx)->get_deep(insert_idx-1)) goto out;

    p->get_value(idx)->insert(p->get_value(idx)->begin() + insert_idx, get_random(0,0xffffffffffffffff));
    p->get_sinfo(idx)->structinfo.insert(p->get_sinfo(idx)->structinfo.begin() + insert_idx, p->get_sinfo(idx)->structinfo.at(insert_idx-1));
    if(p->inuse == SYSCALL)
      p->op.sysc->at(idx)->nargno.insert(p->op.sysc->at(idx)->nargno.begin() + insert_idx, p->op.sysc->at(idx)->nargno.at(insert_idx-1));
  }

out:
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
