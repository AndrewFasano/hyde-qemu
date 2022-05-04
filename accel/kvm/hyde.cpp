#include <stdio.h>
#include <linux/kvm.h>
#include <cstring>
#include "qemu/compiler.h"
#include "hyde.h"

// This file is largely decoupled from QEMU internals. We issue
// IOCTLs to the kvm vcpu using an extern function with an opaque CPUState pointer
// but that's it. on_syscall and on_sysret are called as necessary by kvm-all.c
//
// The logic in here is split out so we can use C++ features for state management

long unsigned int last_exec_asid = 0;
long unsigned int just_coopted = 0;
struct kvm_regs coopted_regs = {0};

extern "C" void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc) {
#if 0 // exec logger + replacer
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
#endif
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
}

extern "C" void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid, long unsigned int pc) {
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
}
