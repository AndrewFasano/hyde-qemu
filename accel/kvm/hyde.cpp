// This file is largely decoupled from QEMU internals. We issue
// IOCTLs to the kvm vcpu using an extern function with an opaque CPUState pointer
// but that's it. on_syscall and on_sysret are called as necessary by kvm-all.c
// The logic in here is split out so we can use C++ features for state management

#include <asm/unistd.h> // Syscall numbers
#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <linux/kvm.h>
#include <map>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>

#include "qemu/compiler.h"
#include "hyde.h"
#include "hyde_internal.h"

void dprintf(const char *fmt, ...) {
#ifdef DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
}

void set_regs_to_syscall(asid_details* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig) {
    struct kvm_regs r;
    memcpy(&r, orig, sizeof(struct kvm_regs));
    set_CALLNO(r, sysc->callno); // callno is always RAX
                                  // Arguments vary by OS

    //dprintf("Applying syscall to registers:");
    //dump_syscall(*sysc);


#ifdef WINDOWS
    if (sysc->nargs > 0) r.r10 = sysc->args[0];
    if (sysc->nargs > 1) r.rdx = sysc->args[1];
    if (sysc->nargs > 2) r.r8  = sysc->args[2];
    if (sysc->nargs > 3) r.r9  = sysc->args[3];
#define N_STACK 4

#else
    if (sysc->nargs > 0) set_ARG0(r, sysc->args[0]);
    if (sysc->nargs > 1) set_ARG1(r, sysc->args[1]);
    if (sysc->nargs > 2) set_ARG2(r, sysc->args[2]);
    if (sysc->nargs > 3) set_ARG3(r, sysc->args[3]);
    if (sysc->nargs > 4) set_ARG4(r, sysc->args[4]);
    if (sysc->nargs > 5) set_ARG5(r, sysc->args[5]);
#define N_STACK 6
#endif

    // TODO: test and debug this - what linux syscall has > 6 args?
		if (sysc->nargs > N_STACK) {
			printf("Syscall has %d args, > max %d\n", sysc->nargs, N_STACK);
      assert(0 && "untested"); // TODO test
      unsigned long int *stack;

      // XXX: Do we need to unshift later? I don't think so, because we restore regs on ret
      // Above top of stack can have a redzone of 128 bytes - skip that much then add space for args
      r.rsp -= 0x80; // Fixed size of redzone
      r.rsp -= 0x8 * (sysc->nargs - 4);
      printf("Sub'd RSP 0x88: %llx\n", r.rsp);

      // Note this could fail - no easy way to inject a syscall from in this fn
      stack = (unsigned long int*)memread(details, r.rsp, nullptr);
      assert((__u64)stack != (__u64)-1 && "whoops: failed to read stack during injection");

      for (size_t i=4; i < sysc->nargs; i++) {
        printf("\tstack[%ld] = arg[%ld] = %lx\n", sysc->nargs-i, i, sysc->args[i]);
        stack[(sysc->nargs + 4)-i] = sysc->args[i];
      }
    }
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &r) == 0);

    //printf("After application, registers are:\n");
    //dump_regs(r);
}


bool is_syscall_targetable(int callno, unsigned long asid) {
#ifndef WINDOWS
  // Linux specific: avoid sigreturn and seccomp'd processes

  if (callno == 15 || callno == __NR_rt_sigreturn) { // 15 is sigreturn
    // We should never interfere with these, even if we're co-opting a process
    // Note these do not return so we only have to worry about them here
    return false;
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
    return false;
  }
#endif
  return true;
}

asid_details* find_and_init_coopter(void* cpu, int callno, unsigned long asid, unsigned long pc) {
  asid_details *a = NULL;
  struct kvm_regs r;
  //for (coopter_f* coopter : coopters) {
  unsigned long cpu_id = get_cpu_id(cpu);
  for (const auto &pair : coopters) { // For each coopter, see if it's interested. First to return non-null wins
    coopter_f* coopter = pair.second;
    create_coopt_t *f = (*coopter)(cpu, callno, pc, asid);
    if (f != NULL) {
      //dprintf("\n----------\n\nCREATE coopter for %s in %lx on cpu %ld\n", pair.first.c_str(), asid, cpu_id);
      //printf("[CREATE coopter for %s in %lx on cpu %ld before syscall %d at %lx]\n", pair.first.c_str(), asid, cpu_id, callno, pc);
      // A should_coopt function has returned non-null, set this asid
      // up to be coopted by the coopter generator which it returned
      a = new asid_details;

      active_details[{asid, cpu_id}] = a;
      a->cpu = cpu;
      a->asid = asid;
      a->custom_return = 0;
      a->use_orig_regs = false;

      // Get & store original registers before we run the coopter's first iteration
      assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0);
      //dump_regs(r);
      memcpy(&a->orig_regs, &r, sizeof(struct kvm_regs));

      a->orig_syscall = new hsyscall;
      a->orig_syscall->nargs = 6;
      a->orig_syscall->callno = CALLNO(r);
      a->orig_syscall->args[0] = ARG0(r);
      a->orig_syscall->args[1] = ARG1(r);
      a->orig_syscall->args[2] = ARG2(r);
      a->orig_syscall->args[3] = ARG3(r);
      a->orig_syscall->args[4] = ARG4(r);
      a->orig_syscall->args[5] = ARG5(r);
      a->orig_syscall->has_retval = false;

      dprintf("Co-opter starts from: ");
      dump_syscall(*a->orig_syscall);


      // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
      // The value we get in rflags won't match the value that emulate_syscall is putting
      // into rflags - so we compute it ourselves
      //a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;
      // XXX: Why don't we need/want that anymore?

      // XXX: this *runs* the coopter function up until its first co_yield/co_ret
      dprintf("Start running coopter:\n");
      a->coopter = (*f)(active_details[{asid, cpu_id}]).h_;
      dprintf("\t[End of first step]\n");
      return a;
    }
  }

  return NULL;
}

extern "C" void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc,
                           long unsigned int orig_rcx, long unsigned int orig_r11) {
  asid_details *a = NULL;
  bool first = false;

  if (!is_syscall_targetable(callno, asid)) {
    return;
  }
  unsigned long cpu_id = get_cpu_id(cpu);

  if (!active_details.contains({asid, cpu_id})) {
    // No active co-opter for asid - check to see if any want to start
    // If we find one, we initialize it, running to the first yield/ret
    a = find_and_init_coopter(cpu, callno, asid, (unsigned long)pc);
    if (a == NULL) {
      return; 
    }
    a->orig_rcx = orig_rcx;
    a->orig_r11 = orig_r11;

    first = true;
  } else {
    // We already have a co-opter for this asid, it should have been
    // advanced on the last syscall return
    a = active_details.at({asid, cpu_id});

    // No value in fetching regs again, they're the same
    //struct kvm_regs tmp;
    //assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &tmp) == 0);
    //assert(memcmp(&tmp, &a->orig_regs, sizeof(struct kvm_regs)) == 0);
  }

  //printf("Syscall in active %lx on cpu %ld: callno: %ld\n", asid, cpu_id, callno);

  // In general, we'll store the original syscall and require the *user*
  // to run it when they want it to happen (e.g., start or end)
  // Original syscall will be mutable.

  hsyscall sysc;
  sysc.nargs = (unsigned int)-1;
  auto &promise = a->coopter.promise();

  if (!a->coopter.done()) {
    // We have something to inject
    sysc = promise.value_;
    dprintf("We have something to inject in %lx at PC %lx:\n\t", asid, pc);
    dump_syscall(sysc);

  } else if (first) {
    // Nothing to inject and this is the first syscall
    // so we need to run a skip! We do this with a "no-op" syscall
    // and hiding the result on return
    //printf("SKIP0\n");
    if (!a->orig_syscall->has_retval) {
      // No-op: user registered a co-opter but it did nothing so we're already done
      printf("Warning: co-opter did nothing: ignoring it\n");
      a->coopter.destroy();
      active_details.erase({asid, cpu_id});
      return;
    }
    sysc.nargs = 0;
    sysc.callno = SKIP_SYSNO;
    sysc.has_retval = true;
    sysc.retval = a->orig_syscall->retval;
    printf("Skip original syscall (was %d) in %lx at %lx using new syscall %d and then set RV to %llx\n", a->orig_syscall->callno, asid, pc, sysc.callno, a->orig_syscall->retval);

  } else {
    printf("FATAL: Not done and not first\n");
    assert(0); // This should never happen - if it isn't the first one
               // we would have bailed on the last return if we didn't have more
    return;
  }

  set_regs_to_syscall(a, cpu, &sysc, &a->orig_regs);

  // If it's a non-returning syscall(?) we can't catch it on return - clean up now.
  // Note this means a users can't inject one of these in the middle of a co-opter
  if (sysc.callno == __NR_execve || sysc.callno == __NR_exit) { // XXX: others? fork/kill?
    dprintf("Injecting non-returning syscall: no longer tracing %lx\n", asid);
    a->coopter.destroy();
    active_details.erase({asid, cpu_id});
  }
}

extern "C" void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid,
                          long unsigned int pc) {
  unsigned long cpu_id = get_cpu_id(cpu);
  if (!active_details.contains({asid, cpu_id})) {
    return;
  }
  asid_details *details = active_details.at({asid, cpu_id});

  // If capability wants to finish and set a retval without running another
  // syscall, it can set orig_syscall->retval and orig_syscall->has_retval
  // Then we'll just set this to the retval on the sysret
  if (details->orig_syscall->has_retval) {
    printf("\n***Return from no-op SC in %lx with rv=%lx\n", asid, retval);
  } else {
    details->retval = retval;
    printf("Return from injected syscall in %lx with rv=%lx. Advance coopter:\n", asid, retval);
    details->coopter(); // Advance - will have access to the just returned value
    dprintf("\t[End of subsequent step]\n");
  }

  struct kvm_regs new_regs;
  memcpy(&new_regs, &details->orig_regs, sizeof(struct kvm_regs));

  if (details->coopter.done()) {
    // Co-opter is done. Clean up time
    struct kvm_regs oldregs;
#ifdef DEBUG
    getregs(details, &oldregs);
    dprintf("\tCoopter done, last sc returned %x return to %lx\n", oldregs.rax, pc);
#endif

    if (details->orig_syscall->has_retval) {
      // We set a retval in orig_syscall object, return that
      // This is how we'd do INJECT_SC_A, ORIG_SC, INJECT_SC_B and
      // pretend nothign was injected
      new_regs.rax = details->orig_syscall->retval;
      dprintf("Change return to be %x\n", details->orig_syscall->retval);
    } else {
      // We weren't told the orig_syscall has a retval, that means the last
      // return value shoudl be what we pass back. This is how we'd do
      // INJECT_SC_A, INJECT_SC_B, ORIG.
      getregs(details, &oldregs);
      new_regs.rax = oldregs.rax;
    }

    if (details->use_orig_regs) {
      new_regs.rcx = details->orig_rcx;
      new_regs.r11 = details->orig_r11;
      /// XXX: eflags is also changed, but that's not so important? Also not sure how to cleanly restore
    }

    if (details->custom_return != 0) {
      new_regs.rip = details->custom_return;
    } else {
      new_regs.rip = pc; // XXX we *do* need to explicitly set this to
                         // return back to userspace, otherwise rip is
                         // the LSTAR value, not the next userspace insn.
                         // I assume this is because of a delay with KVM updating
                         // registers, not because there's more to do in the LSTAR
                         // kernel code.
      }

    details->coopter.destroy();
    active_details.erase({asid, cpu_id});
  } else {
    dprintf("Not done - go back to %lx\n", pc-2);
    new_regs.rip = pc-2; // Take it back now, y'all
  }
  assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &new_regs) == 0);
}

void enable_syscall_introspection(void* cpu, int idx) {
  assert(cpu != nullptr);
  assert(kvm_vcpu_ioctl_pause_vm(cpu, KVM_HYDE_TOGGLE, 1) == 0);
}

void disable_syscall_introspection(void* cpu) {
  assert(cpu != nullptr);
  assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
}

bool try_load_coopter(std::string path, void* cpu, int idx) {
  if (coopters.count(path)) {
    if (idx == 0) {
      printf("Already have %s capability loaded\n", path.c_str());
      return false;
    }
      return true; // Cap already loaded for 0th CPU
  }
  void* handle = dlopen(path.c_str(), RTLD_LAZY);
  if (handle == NULL) {
    printf("Could not open capability at %s: %s\n", path.c_str(), dlerror());
    return false;
  }

  coopter_f* do_coopt;
  do_coopt = (coopter_f*)dlsym(handle, "should_coopt");
  if (do_coopt == NULL) {
    printf("Could not find should_coopt function in capability: %s\n", dlerror());
    dlclose(handle);
    return false;
  }
  if (coopters.empty()) {
    enable_syscall_introspection(cpu, idx);
  }
  coopters[path] = *do_coopt;
  return true;
}

bool try_unload_coopter(std::string path, void* cpu, int idx) {
  if (!coopters.count(path)) {
    if (idx == 0) {
      printf("Capability %s has not been loaded\n", path.c_str());
      return false;
    }
    return true; // Already unloaded for 0th cpu??
  }
  coopters.erase(path);
  if (coopters.empty()) {
    disable_syscall_introspection(cpu);
  }
  return true;
}

extern "C" bool kvm_load_hyde_capability(const char* path, void *cpu, int idx) {
  return try_load_coopter(std::string(path), cpu, idx);
}

extern "C" bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx) {
  return try_unload_coopter(std::string(path), cpu, idx);
}

extern "C" void hyde_init(void) {
  //const char* path = "/home/andrew/hhyde/cap_libs/cap.so";
  //assert(try_load_coopter(path));
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


SyscCoroutine new_memread(asid_details* r, __u64 gva, void* out, size_t size) {
  // We wish to read size bytes from the guest virtual address space
  // and store them in the buffer pointed to by out. If out is NULL,
  // we allocate it

  struct kvm_translation trans = { .linear_address = gva };
  //printf("Trying to read %llx\n", trans.linear_address);
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  // Translation failed on base address - not in our TLB, maybe paged out
  if (trans.physical_address == (unsigned long)-1) {
      build_syscall(&r->scratch, __NR_access, gva, 0);
      co_yield r->scratch; // Don't need RV in r->retval

      // Now retry. if we fail again, bail
      //printf("Retrying to read %llx\n", trans.linear_address);
      assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);
      //printf("\t result: %llx\n", trans.physical_address);
      assert(trans.physical_address != (unsigned long)-1);
  }

  // Translation has succeeded, we have the guest physical address
  // Now translate that to the host virtual address
  __u64 hva;
  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &hva) == 1);
  //printf("Gva %llx => gpa %llx => hva %llx -> host data %llx\n", gva, trans.physical_address, hva, *(__u64*)hva);
  memcpy((uint64_t*)out, (void*)hva, size);

  #if 0
  // For each page starting at gva:
  #define PAGE_SIZE 0xFFFF
  size_t offset = gva % PAGE_SIZE;

  for (__u64 page_base = gva - offset; page_base < gva + size; page_base += PAGE_SIZE) {
    // Translate the page base (guest virtual address) to a guest physical address
    struct kvm_translation trans = { .linear_address = page_base };
    assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

    // Translation failed on base address - not in our TLB, maybe paged out
    if (trans.physical_address == (unsigned long)-1) {
        build_syscall(&r->scratch, __NR_access, page_base, 0);
        co_yield r->scratch;
        // Don't need RV in r->retval

        // Now retry. if we fail again, bail
        assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);
        assert(trans.physical_address != (unsigned long)-1);
    }

    // Translation has succeeded, we have the guest physical address
    // Now translate that to the host virtual address
    __u64 hva;
    assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &hva) == 1);

    //char* out_ptr = (char*)out + (page_base - gva);

    size_t bytes_to_read = std::min(PAGE_SIZE, (int)(size - offset));

    memcpy(out + (page_base - gva ), (void*)(hva + offset), bytes_to_read);
    size -= bytes_to_read;
    offset = 0; // Only relevant for first iteration
  }
  #endif
  co_return;
}