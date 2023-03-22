// This file is largely decoupled from QEMU internals. We issue
// IOCTLs to the kvm vcpu using an extern function with an opaque CPUState pointer
// but that's it. on_syscall and on_sysret are called as necessary by kvm-all.c
// The logic in here is split out so we can use C++ features for state management

#include <algorithm>
#include <asm/unistd.h> // Syscall numbers
#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <linux/kvm.h>
#include <map>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <sys/syscall.h>

#include "qemu/compiler.h"
#include "exec/hwaddr.h" // for hwaddr typedef
//#include "accel/kvm/kvm-cpus.h" // for kvm_host_addr_from_physical_memory
extern "C" int kvm_host_addr_from_physical_memory(hwaddr gpa, hwaddr *phys_addr);

#include "hyde_common.h"
#include "hyde_internal.h"

void dprintf(const char *fmt, ...) {
#ifdef DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
}

// Expose some KVM functions externally
template <typename... Args>
int kvm_vcpu_ioctl_ext(void *cpu, int type, Args... args) {
  return kvm_vcpu_ioctl(cpu, type, args...);
}

int kvm_host_addr_from_physical_memory_ext(uint64_t gpa, uint64_t *phys_addr) {
  return kvm_host_addr_from_physical_memory((hwaddr)gpa, (hwaddr*)phys_addr);
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
  // TODO: can we also support non-absolute paths?
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

bool kvm_unload_hyde(void *cpu, int idx) {
  // For each in coopters,
  for (auto it = coopters.begin(); it != coopters.end(); ++it) {
    printf("Unloading %s\n", it->first.c_str());
    try_unload_coopter(it->first, cpu, idx);
  }
  return true;
}

bool kvm_load_hyde_capability(const char* path, void *cpu, int idx) {
  return try_load_coopter(std::string(path), cpu, idx);
}

bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx) {
  return try_unload_coopter(std::string(path), cpu, idx);
}

int getregs(asid_details *r, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, regs);
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

bool can_translate_gva(void*cpu, uint64_t gva) {
  struct kvm_translation trans = { .linear_address = (__u64)gva };

  // Requesting the translation shouldn't ever fail, even though
  // the translated result might be that the translation failed
  assert(kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &trans) == 0);

  // Translation ok if valid and != -1
  return (trans.valid && trans.physical_address != (unsigned long)-1);
}

/* Given a GVA, try to translate it to a host address.
 * return indicates success. If success, host address 
 * will be set in hva argument. */
bool translate_gva(asid_details *r, uint64_t gva, uint64_t* hva) {
  if (!can_translate_gva(r->cpu, gva)) {
    return false;
  }
  // Duplicate some logic from can_translate_gva so we can get the physaddr here
  struct kvm_translation trans = { .linear_address = (__u64)gva };
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  assert(kvm_host_addr_from_physical_memory(trans.physical_address, (uint64_t*)hva) == 1);
  return true;
}

// TODO: could we convert this to a co-routine so it could yield helpers in order to reliably access stack
void set_regs_to_syscall(asid_details* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig) {
    struct kvm_regs r;
    memcpy(&r, orig, sizeof(struct kvm_regs));
    set_arg(r, RegIndex::CALLNO, sysc->callno);
                                  // Arguments vary by OS
    //dprintf("Applying syscall to registers:");

#ifdef WINDOWS
    if (sysc->nargs > 0) r.r10 = sysc->args[0];
    if (sysc->nargs > 1) r.rdx = sysc->args[1];
    if (sysc->nargs > 2) r.r8  = sysc->args[2];
    if (sysc->nargs > 3) r.r9  = sysc->args[3];
#define N_STACK 4

#else
#define N_STACK 6u
    for (int i = 0; i < std::max(N_STACK, sysc->nargs); i++) {
        set_arg(r, (RegIndex)i, sysc->args[i]);
    }
#endif

    // TODO: test and debug this - what linux syscall has > 6 args?
		if (sysc->nargs > N_STACK) {
			printf("Syscall has %d args, > max %d\n", sysc->nargs, N_STACK);
      assert(0 && "NYI support stack-based arguments"); // TODO test
    }
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &r) == 0);
}

bool is_syscall_targetable(int callno, unsigned long asid) {
#ifndef WINDOWS
  // On linux guests we have two cases where we should never inject a syscall
  // 1. If the syscall is sigreturn or rt_sigreturn: these are used to restore
  //   the signal mask and other state after a signal handler returns. If we
  //   inject a syscall into one of these, we'll cause problems for the guest
  // 2. If the process has used seccomp previously - in this case it is only
  //   allowed to make syscalls that are explicitly allowed by the seccomp
  //  filter. Since we don't know what's allowed, we'll ignore it.

  if (callno == __NR_rt_sigreturn) {
    // Note these do not return so we only have to worry about them here
    return false;
  }

  if (callno == __NR_seccomp) {
    // Record that this asid has used seccomp and avoid it until it quits
    did_seccomp.insert(asid);
  }
  if (did_seccomp.find(asid) != did_seccomp.end()) {
    if (callno == __NR_exit || callno == __NR_exit_group) { // sys_exit, sys_exitgroup
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
  unsigned long cpu_id = get_cpu_id(cpu);
  for (const auto &pair : coopters) { // For each coopter, see if it's interested. First to return non-null wins
    coopter_f* coopter = pair.second;
    create_coopt_t *f = (*coopter)(cpu, callno, pc, asid);
    // if a should_coopt function returns non-null, set this asid up to be coopted
    // by the coopter generator which it returned.
    if (f == NULL) {
      //printf("Should coopt for %d returns NULL\n", callno);
      return NULL; // XXX: should this be a continue?
    }

    //printf("[CREATE coopter for %s in %lx on cpu %ld before syscall %d at %lx]\n", pair.first.c_str(), asid, cpu_id, callno, pc);

    // Get & store original registers before we run the coopter's first iteration
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &r) == 0); //dump_regs(r);

    a = new asid_details {
      .orig_syscall = new hsyscall {
        .callno = get_arg(r, RegIndex::CALLNO),
        .nargs = 6,
        .has_retval = false,
      },
      .cpu = cpu,
      .asid = asid,
      .use_orig_regs = false,
      .custom_return = 0,
    };

    for (int i = 0; i < 6; i++) {
      a->orig_syscall->args[i].value = get_arg(r, (RegIndex)i);
      a->orig_syscall->args[i].is_ptr = false;
    }
    memcpy(&a->orig_regs, &r, sizeof(struct kvm_regs));

    // This ends our maybe race condition - we've built the asid_details entry
    active_details[{asid, cpu_id}] = a;

    // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
    // The value we get in rflags won't match the value that emulate_syscall is putting
    // into rflags - so we compute it ourselves
    //a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;
    // XXX: Why don't we need/want that anymore?

    // XXX: this *runs* the coopter function up until its first co_yield/co_ret
    a->coopter = (*f)(active_details[{asid, cpu_id}]).h_;
    a->name = pair.first;
    return a;
  }

  return NULL;
}

void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc,
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
    dprintf("Have existing coopter from {%lx, %lx}\n", asid, cpu_id);
    a = active_details.at({asid, cpu_id});
    // No value in fetching regs again, they're the same
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
    printf("Skip original syscall (was %ld) in %lx at %lx using new syscall %ld and then set RV to %lx\n", a->orig_syscall->callno, asid, pc, sysc.callno, a->orig_syscall->retval);

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

void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid, long unsigned int pc) {
  unsigned long cpu_id = get_cpu_id(cpu);
  if (!active_details.contains({asid, cpu_id})) {
    return;
  }
  asid_details *details = active_details.at({asid, cpu_id});

  // If capability wants to finish and set a retval without running another
  // syscall, it can set orig_syscall->retval and orig_syscall->has_retval
  // Then we'll just set this to the retval on the sysret
  if (details->orig_syscall->has_retval) {
    dprintf("\n***Return from no-op (er, actually %lu) SC in %lx with rv=%lx\n", details->orig_syscall->callno, asid, retval);
  } else {
    details->last_sc_retval = (uint64_t)retval;
    dprintf("Return from injected syscall in %lx with rv=%lx. Advance coopter:\n", asid, retval);
  }
  // If we set has_retval, it's in a funky state - we need to advance it so it will finish, otherwise we'll
  // keep yielding the last (no-op) syscall over and over again
  details->coopter(); // Advance - will have access to the just returned value
  dprintf("\t[End of subsequent step]\n");

  struct kvm_regs new_regs;
  memcpy(&new_regs, &details->orig_regs, sizeof(struct kvm_regs));

  //printf("Done is %d\n", details->coopter.done());

  if (details->coopter.done()) {
    // Co-opter is done. Clean up time

    // Get result
    auto &promise = details->coopter.promise();
    ExitStatus result = promise.retval;

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
      printf("Change return in %lx, %ld to be %lx\n", asid, cpu_id, details->orig_syscall->retval);
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

    if (details->custom_return != 0) { // Custom return *address*
      new_regs.rip = details->custom_return;
    } else {
      new_regs.rip = pc; // XXX we *do* need to explicitly set this to
                         // return back to userspace, otherwise rip is
                         // the LSTAR value, not the next userspace insn.
                         // I assume this is because of a delay with KVM updating
                         // registers, not because there's more to do in the LSTAR
                         // kernel code.
    }

    // Remove this active coopter
    details->coopter.destroy();
    active_details.erase({asid, cpu_id});

    // Based on result, update state for the whole hyde program
    switch (result) {
      case ExitStatus::FATAL:
        printf("[HyDE] Fatal error in %s\n", details->name.c_str());
      case ExitStatus::FINISHED:
        printf("[HyDE] Unloading %s on cpu %d\n", details->name.c_str(), 0);
        try_unload_coopter(details->name, cpu, 0); // XXX multicore guests, need to do for all CPUs?
        break;

      case ExitStatus::SINGLE_FAILURE:
        printf("[HyDE] Warning %s experienced a non-fatal failure\n", details->name.c_str());
        break;

      case ExitStatus::SUCCESS:
        // Nothing to do
        break;
    }
  } else {
    //assert(!details->coopter.promise().did_return);
    dprintf("Not done in %lx, %ld - go back to %lx\n", asid, cpu_id, pc-1);
    new_regs.rip = pc-2; // Take it back now, y'all
  }
  assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &new_regs) == 0);
}
