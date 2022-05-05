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

SyscCoRoutine my_osi_injector(unsigned int start) {
  co_yield 102; // getuid
  co_yield 39; // getpid
}

std::map<long unsigned int, asid_details*> active_details;

extern "C" void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc) {

  asid_details *a;
  coopter_t h;

  if (!active_details.contains(asid)) {
    // No co-opter for the current asid - should we start one? Let's say yes if it's an execve, no otherwise
    if (callno == 59) {
      // First check what the argument is
      struct kvm_regs r;
      assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);

      __u64 fname_ptr = ARG0(r);
      // Translate
      struct kvm_translation t;
      t.linear_address = fname_ptr;
      assert(kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &t) == 0);

      // Translate guest physical address to a host address so we can read/write it
      __u64 phys_addr;
      if (!kvm_host_addr_from_physical_physical_memory(t.physical_address, &phys_addr)) {
        printf("HyDE unable to find host address for guest memory (GVA %llx -> GPA %llx -> HVA %llx => fail)\n", fname_ptr, t.physical_address, phys_addr);
        // TODO: inject access to page it in?
        return;
      }
      char* fname = (char*)phys_addr;
      printf("SYS_exec(%s)\n", fname);

      // Only co-opt if name matches - this is the first exece we see
      if (strcmp(fname, "/proc/self/exe") == 0) {
        h = my_osi_injector(callno).h_;
        // Now save it into our map
        a = new asid_details;
        a->coopter = h;
        a->counter = 0;
        active_details[asid] = a;
      }
    }
  }

  if (!active_details.contains(asid)) {
    return;
  }

  a = active_details.at(asid);
  h = a->coopter;

  auto &promise = h.promise();
	if (!h.done()) {
		printf("[HYDE] Co-opter in %lx injects %d-th syscall: #%d\n", asid, a->counter++, promise.value_);
    //h(); // XXX: be sure to advance generator so we don't duplicate injection -- XXX should this be in on return?
    a->last_inject = promise.value_;

    // First store original registers
    struct kvm_regs r;
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);

    memcpy(&a->orig_regs, &r, sizeof(r));

    // Then update state to inject desired syscall (in promise.value_)
    set_CALLNO(r, promise.value_);
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

  // Store retval
  a->retval = retval;

  if ((long int) retval < 0) {
    printf("[HYDE] After running injected #%ld in %lx we got a negative retval of %ld (0x%lx)\n", a->last_inject, asid, (long int) retval, retval);
  }else{
    printf("[HYDE] After running injected #%ld in %lx we got a retval of 0x%lx\n", a->last_inject, asid, retval);
  }

  // Advance generator (so it's ready for next injection) TODO: get retval into coopter itself!
  a->coopter();

  a->orig_regs.rip = pc-2; // Take it back now, y'all
  assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
}

#if 0 // exec logger + replacer
long unsigned int last_exec_asid = 0;
long unsigned int just_coopted = 0;
// in on_syscall...
  if (unlikely(callno == 59)) {
      struct kvm_regs regs;
      int rv = kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &regs);
      if (rv != 0) {
        printf("HyDE error reading registers: %d\n", rv);
        return;
      }
      __u64 fname_ptr = ARG0(regs);

      // Translate
      struct kvm_translation t;
      t.linear_address = fname_ptr;
      rv = kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &t);
      if (rv != 0) {
        printf("HyDE error reading translating: %d\n", rv);
        return;
      }

      // Translate guest physical address to a host address so we can read/write it
      KVMState *s = KVM_STATE(current_accel());
      hwaddr phys_addr;
      if (!kvm_host_addr_from_physical_physical_memory(s, t.physical_address, &phys_addr)) {
        printf("HyDE unable to find host address for guest memory (GVA %llx -> GPA %llx -> HVA %lx => fail)\n", fname_ptr, t.physical_address, phys_addr);
      }
      //printf("GVA %llx -> GPA %llx -> HVA %lx => %s\n", fname_ptr, t.physical_address, phys_addr, (char*)phys_addr);
      char* fname = (char*)phys_addr;
      printf("SYS_exec(%s)\n", fname);

      //if (strcmp(fname, "/bin/true") == 0) {
      //  printf("\tFLIP\n");
      //  memcpy(fname, "/bin/bash", 10);
      //}
  }
// Next
  // When we see a SYS_READ, we'll coopt it with a GETUID then let it run for real
  if (unlikely(callno == 0)) {
    struct kvm_regs regs;
    int rv = kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &regs);
    if (rv != 0) {
      printf("HyDE error reading registers: %d\n", rv);
      return;
    }

    if (last_exec_asid == 0 && asid != just_coopted) {
      printf("SYS_read in %lx of %llx\n", asid, ARG0(regs));
      last_exec_asid = asid;
      memcpy(&coopted_regs, &regs, sizeof(regs));

      // Change callno to GETUID
      set_CALLNO(regs, 102);

      rv = kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &regs);
      if (rv != 0) {
        printf("HyDE error updating registers: %d\n", rv);
        return;
      }
    }
  }
#endif

#if 0
  if (asid == last_exec_asid) {
    printf("Co-opted read->GETUID in %lx returned at %lx with value %d\n", asid, pc, (int)retval);
    coopted_regs.rip = pc-2; // Take it back now, y'all
    int rv = kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &coopted_regs);
    last_exec_asid = 0;
    just_coopted = asid;
    if (rv != 0) {
      printf("HyDE error updating registers: %d\n", rv);
      return;
    }
  }
#endif
