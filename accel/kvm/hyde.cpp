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
  asid_details *a = NULL;
  struct kvm_regs r;

#ifndef WINDOWS
  // Linux specific: avoid sigreturn and seccomp'd processes

  if (callno == 15 || callno == __NR_rt_sigreturn) { // 15 is sigreturn
    // We should never interfere with these, even if we're co-opting a process
    // Note these do not return so we only have to worry about them here
    return;
  }

  if (callno == 317) { // sys_seccomp
    // This asid is using SECOMP let's never inject into it
    did_seccomp.insert(asid);
  }
  if (did_seccomp.find(asid) != did_seccomp.end()) {
    if (callno == 60 || callno == 231) { // sys_exit, sys_exitgroup
      // An asid we've been avoiding is quitting - remove from our avoid list
      did_seccomp.erase(asid);
    }
    return;
  }
#endif

  if (!active_details.contains(asid)) {
    // No co-opter for the current asid. Check with all registered coopters to see if any
    // want to start on this syscall.
    bool match = false;
    for (coopter_f* coopter : coopters) {
      create_coopt_t *f = (*coopter)(cpu, callno);
      if (f != NULL) {
#ifdef DEBUG
        printf("\n----------\n\nCREATE coopter in %lx\n", asid);
#endif
        // A should_coopt function has returned non-null, set this asid
        // up to be coopted by the coopter generator which it returned
        a = new asid_details;
        active_details[asid] = a;
        a->cpu = cpu;
        a->asid = asid;
        a->skip = false;
        //a->finished = false;
        a->modify_original_args = false;
        a->custom_return = 0;

        // Get & store original registers before we run the coopter's first iteration
        assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);
        memcpy(&a->orig_regs, &r, sizeof(r));
        // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
        // The value we get in rflags won't match the value that emulate_syscall is putting
        // into rflags - so we compute it ourselves
        a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;

        // XXX: this *runs* the coopter function up until its first co_yield/co_ret
        a->coopter = (*f)(active_details[asid]).h_;
        match = true;
        break;
      }
    }
    if (!match) {
      // No active co-opter for this asid, and none wanted to start so let's leave it alone
      return; 
    }
  } else {
    // We have a co-opter for this asid. Let's advance it here!
    a = active_details.at(asid);
 
    // Set orig regs so co-opter can see them
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);
    memcpy(&a->orig_regs, &r, sizeof(r));
    a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2; // See comment above

    // Now advance co-opter. If it yields, we inject below
    a->coopter();
  }

  // By here `a` should always be set, otherwise we returned
  assert(a != NULL);

  // The co-opter has run (either from init or in the last sysret) up to a yield/ret
  if (a->modify_original_args) {
    // If it wanted to modify original registers (i.e., it's *not* injecting a syscall)
    // then we set registers to whatever it stored (i.e., modified) in orig_regs
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
  }

  hsyscall sysc;
  sysc.nargs = (unsigned int)-1;
  if (a->skip) {
    // We "skip" by running a no-op and cleaning up on return
    // because we've already run the `syscall` instruction
    // and we want to run the corresponding `sysret` to clean it up
    // instead of trying to do that all from here.
#ifdef WINDOWS
    sysc.nargs = 0; // NtTestAlert - Probably want to find a better no-o
    sysc.callno = 0x01c0;
#else
    sysc.nargs = 0;
    sysc.callno = __NR_getuid;
#endif
    // On return, we'll restore orig_regs - caller who requested the skip should modify those

  } else {
    auto &promise = a->coopter.promise();
    if (!a->coopter.done()) {
      // The coopter yielded a syscall
      sysc = promise.value_;
    }else{
      // The coopter returned - leave sysc with nargs=-1
    }
  }

  if (sysc.nargs != (unsigned int)-1) {
    // Coopter yielded a syscall which we have in sysc.
    // Now update registers (r) such that the syscall is run
    set_CALLNO(r, sysc.callno); // callno is always RAX
                                // Arguments vary by OS
#ifdef WINDOWS
    if (sysc.nargs > 0)
      r.r10 = sysc.args[0];
    if (sysc.nargs > 1)
      r.rdx = sysc.args[1];
    if (sysc.nargs > 2)
      r.r8 = sysc.args[2];
    if (sysc.nargs > 3)
      r.r9 = sysc.args[3];

    if (sysc.nargs > 4) {
      unsigned long int *stack;

      // XXX: Do we need to unshift later? I don't think so, because we restore regs on ret
      r.rsp -= 0x38; // TODO: dynamic based on nargs

      // Note this could fail - no easy way to inject a syscall from in this fn
      stack = (unsigned long int*)memread(a, r.rsp, nullptr);
      assert((__u64)stack != (__u64)-1 && "whoops: failed to read stack during injection");

      // I have no idea what's on the stack between 0 and 0x28 (up to stack[4]) - assuming it's
      // all just junk - so we shift RSP far enough that we can write at +0x20 without
      // any issues
      if (sysc.nargs > 4) {
        stack[5] = sysc.args[4];
        //printf("Set stack[5] to %lx\n", sysc.args[4]);
      }

      if (sysc.nargs > 5) {
        stack[6] = sysc.args[5];
        //printf("Set stack[6] to %lx\n", sysc.args[5]);
      }
    }
#else
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
      set_ARG5(r, sysc.args[5]);
#endif

    //dump_sc_with_stack(a, r); // DEBUG

    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &r) == 0);

    // DEBUG: log clobered registers
#ifdef DEBUG
    a->injected_callno = sysc.callno;
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);
    if (!a->skip) {
      printf("In asid %lx @ %lx △> ", asid, pc);
      dump_regs(r);
    }
#endif

  } else {
    // At this point, the original syscall is about to be issued (any prior changes
    // were cleaned up in the last sysret). If the co-opter wishes to change the
    // current syscall, it would have indicated by setting modify_original_args
    // and changing orig_args
		a->coopter.destroy();
		active_details.erase(asid);
    //a->finished = true;
#ifdef DEBUG
    printf("In asid %lx @ %lx ]] allow original syscall %llx\n", asid, pc, CALLNO(a->orig_regs));
#endif
	}
}

extern "C" void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid, long unsigned int pc) {
  if (!active_details.contains(asid)) {
    return;
  }
  asid_details * a = active_details.at(asid);

  // We co-opted this syscall - store it's retval and reset state!
#ifdef DEBUG
  printf("In asid %lx @ %lx << return from coopted syscall. Original was %lld, injected was %d, returns %lx\n",
      asid, pc,
      CALLNO(a->orig_regs), a->injected_callno, retval);
#endif

  if (a->skip) {
    // We skipped the original syscall, replacing it with a getuid / NtYieldExec
    // let's clean up by restoring orig_regs with the *pc after syscall*
    // (it's just `pc`, not decremented like we normally do) Note that we
    // *won't* hit the sysenter case again for this (asid,syscall) because
    // there's no revert. So we clean it all up here and don't bother with .finished
    if (a->custom_return == 0){
      a->orig_regs.rip = pc;
    }else{
      // A capability can specify a custom return address if it wishes
      a->orig_regs.rip = a->custom_return;
    }
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
		a->coopter.destroy();
		active_details.erase(asid);
    return;
  }else if (!a->coopter.done()) {
    // If it's not finished, we'll go back to the original PC

    a->orig_regs.rip = pc-2; // Take it back now, y'all
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &a->orig_regs) == 0);
#ifdef DEBUG
    printf("\tRevert to PC %lx with registers:\n", pc-2);
    dump_regs(a->orig_regs);
  } else {
    // Finished and it doesn't want to skip
    // XXX: what if we shifted RSP in the last syscall we injected? TODO XXX need to handle
    // this would happen if we injected with > 4 args and skip
    printf("\tCo-opter done\n");
#endif
  }

  // Store retval then and advance generator - note its return (the next syscall to inject) won't be
  // consumed until the next syscall.
  a->retval = retval;
}

bool try_load_coopter(char* path) {
  void* handle = dlopen(path, RTLD_LAZY);
  if (handle == NULL) {
    printf("Could not open capability at %s: %s\n", path, dlerror());
    assert(0);
  }

  coopter_f* do_coopt;
  do_coopt = (coopter_f*)dlsym(handle, "should_coopt");
  if (do_coopt == NULL) {
    printf("Could not find do_coopt function in capability: %s\n", dlerror());
    return false;
  }
  coopters.push_back(*do_coopt);
  return true;
}

extern "C" void hyde_init(void) {
  const char* path = "/home/andrew/hhyde/cap_libs/cap.so";
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
  if (nargs > 5) s->args[5] = arg5;
}
void build_syscall(hsyscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3, int unsigned long arg4,
    int unsigned long arg5) {
  _build_syscall(s, callno, 6, arg0, arg1, arg2, arg3, arg4, arg5);
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
#ifdef WINDOWS
      // Inject NtLoadDriver(gva). XXX will have side effects if gva is a pointer to
      // a UNICODE_STRING struct with a value that starts with
      // '\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\' and has Type=1
      // XXX Might not even read pointer if process doesn't have permissions to load drivers?
      //build_syscall(sc, 0x0105, gva);


      // NtUnmapViewOfSection - Will it work with invalid handle?
      //build_syscall(sc, 0x002a, 0, gva); // this just doesn't ever work?


      /* NtReadVirtualMemory
      IN HANDLE               ProcessHandle,
      IN PVOID                BaseAddress,
      OUT PVOID               Buffer,
      IN ULONG                NumberOfBytesToRead,
      OUT PULONG              NumberOfBytesReaded OPTIONAL
      */
      //build_syscall(sc, 0x3f,
      //    -1, // HANDLE = self (-1)
      //    gva, // Pointer to guest buffer
      //    0,   // Out buffer is NULL
      //    100);  // Num bytes to read is 0

      // NtLoadKey - Works well, except when it returns STATUS_PRIVILEGE_NOT_HELD
      // because process lacks SE_RESTORE_PRIVILEGE - frequently...
      //build_syscall(sc, 0x0107, gva, gva);

      // NtDeleteFile - This is scary, what if the buffer somehow
      // was of the right format to get deleted?
      build_syscall(sc, 0x00d2, gva);

#else
      build_syscall(sc, __NR_access, gva, 0);
#endif
      return (__u64)-1;
    } else {
      //printf("[HYDE] Error, could not translate 0x%llx and not able to inject a syscall\n", gva);
      return (__u64)-1;
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

__u64 translate(void *cpu, __u64 gva, int* error) {
  struct kvm_translation trans = {
    .linear_address = gva
  };

  *error = kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &trans); // Zero on success

  if (*error) {
    return (__u64)-1;
  }

  __u64 phys_addr;
  if (kvm_host_addr_from_physical_physical_memory(trans.physical_address, &phys_addr) != 1) {
    *error = true;
    return (__u64)-1;
  }
  return phys_addr;
}

int getregs(void *cpu, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(cpu, KVM_GET_REGS, regs);
}

int setregs(asid_details *r, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(r->cpu, KVM_SET_REGS, &regs) == 0;
}

int setregs(void *cpu, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &regs) == 0;
}
