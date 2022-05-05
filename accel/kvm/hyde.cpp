// This file is largely decoupled from QEMU internals. We issue
// IOCTLs to the kvm vcpu using an extern function with an opaque CPUState pointer
// but that's it. on_syscall and on_sysret are called as necessary by kvm-all.c
// The logic in here is split out so we can use C++ features for state management

#include <asm/unistd.h> // Syscall numbers
#include <cassert>
#include <cstring>
#include <linux/kvm.h>
#include <map>
#include <stdio.h>
#include <vector>
#include "qemu/compiler.h"
#include "hyde.h"
#include "hyde_helpers.h"

std::vector<coopter_pair> coopters; // Pair of bool() which indicates if coopter should start and coopter
std::map<long unsigned int, asid_details*> active_details; // asid->details


extern "C" void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc) {
  asid_details *a;

  if (callno == 15 || callno == __NR_rt_sigreturn) { // 15 is sigreturn
    // We should never interfere with these, even if we're co-opting a process
    // Note these do not return so we only have to worry about them here
    return;
  }

  if (!active_details.contains(asid)) {
    // No co-opter for the current asid - should we start one?
    for (auto & coopter : coopters) {
      if (coopter.first(cpu, callno)) {
        a = new asid_details;
        a->counter = 0;
        a->cpu = cpu;
        active_details[asid] = a;
        a->coopter = coopter.second(active_details[asid]).h_;
        a->skip = false;
        break;
      }
    }
  }

  if (!active_details.contains(asid)) {
    return;
  }

  a = active_details.at(asid);

  auto &promise = a->coopter.promise();
	if (!a->coopter.done()) {
    struct kvm_regs r;
    auto sysc = promise.value_;
    // First store original registers into asid_details
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);
    memcpy(&a->orig_regs, &r, sizeof(r));

    // Then update state to inject desired syscall and args
    set_CALLNO(r, sysc.callno);
    if (sysc.nargs > 0) 
      set_ARG0(r, sysc.args[0]);
    if (sysc.nargs > 1) 
      set_ARG1(r, sysc.args[1]);
    if (sysc.nargs > 2) 
      set_ARG2(r, sysc.args[2]);
    if (sysc.nargs > 3) 
      set_ARG3(r, sysc.args[3]);
    if (sysc.nargs > 4) 
      set_ARG4(r, sysc.args[4]);
    if (sysc.nargs > 5) 
      set_ARG4(r, sysc.args[5]);
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &r) == 0);
	} else {
		a->coopter.destroy();
		active_details.erase(asid);
	}
}

extern "C" void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid, long unsigned int pc) {
  if (!active_details.contains(asid)) {
    return;
  }
  // We co-opted this syscall - store it's retval and reset state!
  asid_details * a = active_details.at(asid);

  // Store retval then and advance generator - note its return (the next syscall to inject) won't be
  // consumed until the next syscall
  a->retval = retval;
  a->coopter();

	if (!a->coopter.done() || a->skip) {
    // If it finished and wants to skip the original, don't restore
    a->orig_regs.rip = pc-2; // Take it back now, y'all
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
  }
}


SyscCoroutine nonroot_id(asid_details* r) {
  // Get guest registers so we can examine the first argument
  struct kvm_regs regs;
  GETREGS(r, regs);

  // Read first argument from guest memory
  syscall sc;
  __u64 fname = memread(r, ARG0(regs), &sc);

  if (fname == (__u64)-1) {
    // Read failed - we need to injrect a syscall
    co_yield sc;
    fname = memread(r, ARG0(regs), nullptr);
  }

  printf("SYS_exec(%s)\n", (char*)fname);
  build_syscall(&sc, __NR_getuid);
  co_yield sc;

  if (r->retval != 0) {
    auto uid = r->retval;

    build_syscall(&sc, __NR_getpid);
    co_yield sc;
    printf("HyDE:  myinj]: Non-root process! UID is %ld PID is %ld\n", uid, r->retval);
  }
}

bool coopt_with_nonroot_id(void*cpu, long unsigned int callno) {
  return callno == 59;
}

extern "C" void hyde_init(void) {
  //coopters.push_back(coopter_pair(&coopt_with_nonroot_id, &nonroot_id));
}
