// This file is largely decoupled from QEMU internals. We issue
// IOCTLs to the kvm vcpu using an extern function with an opaque CPUState pointer
// but that's it. on_syscall and on_sysret are called as necessary by kvm-all.c
// The logic in here is split out so we can use C++ features for state management

#include <stdio.h>
#include <linux/kvm.h>
#include <cstring>
#include "qemu/compiler.h"
#include <map>
#include <cassert>
#include "hyde.h"


SyscCoRoutine my_osi_injector(asid_details* r) {
  // Before we inject anything, let's look at the current name

  // 1) Get guest registers
  struct kvm_regs regs;
  assert(kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, &regs) == 0);

  syscall sc;

  // 2) Read arg0 from guest memory
  __u64 fname_ptr = ARG0(regs);
  struct kvm_translation trans;
  trans.linear_address = fname_ptr;
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  // Couldn't translate - yield a syscall to page it in and then retry
  if (trans.physical_address == (unsigned long)-1) {
    build_syscall(&sc, 21, fname_ptr, 0);
    co_yield sc;

    assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);
    if (trans.physical_address == (unsigned long)-1) {
      printf("[HYDE ERROR] Unable to translate GVA %llx got GPA %llx even after injected access\n", fname_ptr, trans.physical_address);
      co_return;
    }
  }

  __u64 phys_addr;
  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &phys_addr) == 1);
  char* fname = (char*)phys_addr;
  printf("SYS_exec(%s)\n", fname);

  build_syscall(&sc, 102); // getuid
  co_yield sc;

  if (r->retval != 0) {
    auto uid = r->retval;

    build_syscall(&sc, 39); // getpid
    co_yield sc;
    printf("HyDE:  myinj]: Non-root process! UID is %ld PID is %ld\n", uid, r->retval);
  }
}

std::map<long unsigned int, asid_details*> active_details;

extern "C" void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc) {

  asid_details *a;
  coopter_t h;

  if (!active_details.contains(asid)) {
    // No co-opter for the current asid - should we start one? Let's say yes if it's an execve, no otherwise
    if (callno == 59) {
      a = new asid_details;
      a->counter = 0;
      a->cpu = cpu;
      active_details[asid] = a;

      h = my_osi_injector(active_details[asid]).h_;
      a->coopter = h;
    }
  }

  if (!active_details.contains(asid)) {
    return;
  }

  a = active_details.at(asid);
  h = a->coopter;

  auto &promise = h.promise();
	if (!h.done()) {
		//printf("[HYDE] Co-opter in %lx injects %d-th syscall: #%d\n", asid, a->counter++, promise.value_.callno);
    auto sysc = promise.value_;
    a->last_inject = sysc.callno;

    // First store original registers
    struct kvm_regs r;
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);

    memcpy(&a->orig_regs, &r, sizeof(r));

    // Then update state to inject desired syscall and args (in promise.value_.callno/args)
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
		h.destroy();
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

  a->orig_regs.rip = pc-2; // Take it back now, y'all
  assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
}
