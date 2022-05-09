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
#include <dlfcn.h>
#include "qemu/compiler.h"
#include "hyde.h"
#include "hyde_internal.h"

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

	if (!a->coopter.done() || a->skip) {
    // If it finished and wants to skip the original, don't restore
    a->orig_regs.rip = pc-2; // Take it back now, y'all
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
  }

  // Store retval then and advance generator - note its return (the next syscall to inject) won't be
  // consumed until the next syscall.
  a->retval = retval;
  a->coopter();
}

bool try_load_coopter(char* path) {
  void* handle = dlopen(path, RTLD_LAZY);
  if (handle == NULL) {
    printf("Could not open capability at %s: %s\n", path, dlerror());
    assert(0);
  }

  bool (*do_coopt)(void*, long unsigned int);
  do_coopt = (bool (*)(void*, long unsigned int))dlsym(handle, "should_coopt");
  if (do_coopt == NULL) {
    printf("Could not find do_coopt function in capability: %s\n", dlerror());
    return false;
  }
  SyscCoroutine (*coopter)(asid_details*);
  coopter = (SyscCoroutine (*)(asid_details*))dlsym(handle, "start_coopter");
  if (coopter == NULL) {
    printf("Could not find coopter function in capability: %s\n", dlerror());
    return false;
  }
  coopters.push_back(coopter_pair(*do_coopt, *coopter));
  return true;
}

extern "C" void hyde_init(void) {
  const char* path = "/home/andrew/hhyde/cap_libs/envmgr.so";
  assert(try_load_coopter((char*)path));
}

// Gross set of build_syscall functions without vaargs
static void _build_syscall(hsyscall* s, unsigned int callno, int nargs,
    int unsigned long arg0, int unsigned long arg1, int unsigned long arg2,
    int unsigned long arg3, int unsigned long arg4, int unsigned long arg5) {
  s->callno = callno;
  s->nargs = nargs;
  if (nargs > 0) s->args[0] = arg0;
  if (nargs > 1) s->args[1] = arg1;
  if (nargs > 2) s->args[2] = arg2;
  if (nargs > 3) s->args[3] = arg3;
  if (nargs > 4) s->args[4] = arg4;
  if (nargs > 4) s->args[5] = arg5;
}
void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3, int unsigned long arg4,
    int unsigned long arg5) {
  _build_syscall(s, callno, 5, arg0, arg1, arg2, arg3, arg4, arg5);
}

void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3, int unsigned long arg4) {
  _build_syscall(s, callno, 5, arg0, arg1, arg2, arg3, arg4, 0);
}

void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3) {
  _build_syscall(s, callno, 4, arg0, arg1, arg2, arg3, 0, 0);
}

void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2) {
  _build_syscall(s, callno, 3, arg0, arg1, arg2, 0, 0, 0);
}

void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1) {
  _build_syscall(s, callno, 2, arg0, arg1, 0, 0, 0, 0);
}

void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0) {
  _build_syscall(s, callno, 1, arg0, 0, 0, 0, 0, 0);
}

void build_syscall(hsyscall* s, unsigned int callno) {
  _build_syscall(s, callno, 0, /*args:*/0, 0, 0, 0, 0, 0);
}


__u64 memread(asid_details* r, __u64 gva, hsyscall* sc) {
  // Given a GVA, return either a HVA or return -1 with sc set to a syscall which should be run
  // If provided SC is null will assert
  struct kvm_translation trans = {
    .linear_address = gva
  };
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  // Couldn't translate, setup SC to be something to page this in
  if (trans.physical_address == (unsigned long)-1) {
    if (sc != nullptr) {
      build_syscall(sc, __NR_access, gva, 0);
      return (__u64)-1;
    } else {
      printf("[HYDE]: Fatal error, could not translate 0x%llx and not able to inject a syscall\n", gva);
      return (__u64)-1;
      //assert(0);
    }
  }

  // Successfully translated GVA to GPA, now translate to HVA
  __u64 phys_addr;
  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &phys_addr) == 1);
  return phys_addr;
}

int getregs(asid_details *r, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, regs);
}
