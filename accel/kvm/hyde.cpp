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
#include <set>
#include <iomanip>
#include <iostream>
#include <type_traits>
#include <unistd.h>
#include <sys/syscall.h>

//#define DEBUG_LOG // Log every syscall/sysret with some register info to /tmp/trace.txt
//#define HYDE_DEBUG

#ifdef DEBUG_LOG
#include <iostream>
#include <fstream>
#endif

#include "qemu/compiler.h"
#include "exec/hwaddr.h" // for hwaddr typedef
//#include "accel/kvm/kvm-cpus.h" // for kvm_host_addr_from_physical_memory
extern "C" int kvm_host_addr_from_physical_memory(hwaddr gpa, hwaddr *phys_addr);

#include "hyde_common.h"
#include "hyde_internal.h"

void hyde_printf(const char *fmt, ...) {
#ifdef HYDE_DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
}

void pretty_print_kvm_regs(const struct kvm_regs &regs) {
    std::cout << "kvm_regs {" << std::endl;

    PRINT_REG(rax);
    PRINT_REG(rbx);
    PRINT_REG(rcx);
    PRINT_REG(rdx);
    PRINT_REG(rsi);
    PRINT_REG(rdi);
    PRINT_REG(rsp);
    PRINT_REG(rbp);
    PRINT_REG(r8);
    PRINT_REG(r9);
    PRINT_REG(r10);
    PRINT_REG(r11);
    PRINT_REG(r12);
    PRINT_REG(r13);
    PRINT_REG(r14);
    PRINT_REG(r15);
    PRINT_REG(rip);
    PRINT_REG(rflags);

    std::cout << "}" << std::endl;
}



// Expose some KVM functions externally
//template <typename... Args>
//int kvm_vcpu_ioctl_ext(void *cpu, int type, Args... args) {
//  return kvm_vcpu_ioctl(cpu, type, args...);
//}

uint64_t kvm_translate(void* cpu, uint64_t gva) {
  struct kvm_translation trans = { .linear_address = (__u64)gva & (uint64_t)-1}; // Ensure high bits aren't set? Not sure if we need to
  assert(kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &trans) == 0); // can't fail if we do this right
  return trans.physical_address;
}


int kvm_host_addr_from_physical_memory_ext(uint64_t gpa, uint64_t *phys_addr) {
  return kvm_host_addr_from_physical_memory((hwaddr)gpa, (hwaddr*)phys_addr);
}

void enable_syscall_introspection(void* cpu, int idx) {
  assert(cpu != nullptr);
  //printf("Enable syscall introspection on CPU %d at %p\n", idx, cpu);
  assert(kvm_vcpu_ioctl_pause_vm(cpu, KVM_HYDE_TOGGLE, 1) == 0);
}

void disable_syscall_introspection(void* cpu, int idx) {
  assert(cpu != nullptr);
  //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
  assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
}

bool try_load_coopter(std::string path, void* cpu, int idx) {

  if (introspection_cpus.count(idx) == 0) {
    enable_syscall_introspection(cpu, idx);
    introspection_cpus.insert(idx);
    //printf("Enabled syscall introspection on CPU %d at %p\n", idx, cpu);
  }

  if (coopters.count(path)) {
    //printf("Already have %s capability loaded\n", path.c_str());
    return true;
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

  coopters[path] = *do_coopt;
  return true;
}

bool try_unload_coopter(std::string path, void* cpu, int idx) {
  // TODO: can we also support non-absolute paths?
  if (!coopters.count(path)) {
    printf("Capability %s has not been loaded\n", path.c_str());
    return true; // Already unloaded for 0th cpu??
  }
  coopters.erase(path);
  if (coopters.empty()) {
    disable_syscall_introspection(cpu, idx);
  }
  return true;
}

bool kvm_unload_hyde(void *cpu, int idx) {
  // Monitor request hits here. This can't work this simply though
  // because if any are actively coopted, we need to wait for them to finish
  for (auto it = coopters.begin(); it != coopters.end(); ++it) {
    printf("Unloading %s\n", it->first.c_str());
    coopters.erase(it++);
  }

  disable_syscall_introspection(cpu, idx);
  return true;
}

bool kvm_load_hyde_capability(const char* path, void *cpu, int idx) {
  //printf("Loading %s on cpu %d\n", path, idx);
  return try_load_coopter(std::string(path), cpu, idx);
}

bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx) {
  printf("Unload %s on cpu %d\n", path, idx);
  return try_unload_coopter(std::string(path), cpu, idx);
}

int getregs(syscall_context *r, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, regs);
}

int getregs(void *cpu, struct kvm_regs *regs) {
  return kvm_vcpu_ioctl(cpu, KVM_GET_REGS, regs);
}

// special regs
int getsregs(void *cpu, struct kvm_sregs *sregs) {
  return kvm_vcpu_ioctl(cpu, KVM_GET_SREGS, sregs);
}

//int setregs(syscall_context *r, struct kvm_regs *regs) {
//  return kvm_vcpu_ioctl(r->cpu, KVM_SET_REGS, &regs) == 0;
//}

int setregs(void *cpu, struct kvm_regs *regs) {
  //pretty_print_kvm_regs(*regs);
  return kvm_vcpu_ioctl(cpu, KVM_SET_REGS, regs); // Expect 0
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
bool translate_gva(syscall_context *r, uint64_t gva, uint64_t* hva) {
  if (!can_translate_gva(r->cpu, gva)) {
    return false;
  }
  // Duplicate some logic from can_translate_gva so we can get the physaddr here
  struct kvm_translation trans = { .linear_address = (__u64)gva };
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  assert(kvm_host_addr_from_physical_memory(trans.physical_address, (uint64_t*)hva) == 1);
  return true;
}

bool set_regs_to_syscall(syscall_context* details, void *cpu, hsyscall *sysc) {
    bool set_magic_values = false;

    struct kvm_regs r = details->orig_regs;
    set_arg(r, RegIndex::CALLNO, sysc->callno);


#define N_STACK 6u

    for (size_t i = 0; i < std::min(N_STACK, sysc->nargs); i++) {
      set_arg(r, (RegIndex)i, sysc->args[i]);
    }

    // TODO: test and debug this - what linux syscall has > 6 args?
		if (sysc->nargs > N_STACK) {
			printf("Syscall has %d args, > max %d\n", sysc->nargs, N_STACK);
      assert(0 && "NYI support stack-based arguments"); // TODO test
    }

    // If we'll catch the return, we clobber two registers to
    // store state about the syscall. Note we're checking
    // the *set* callno, not the original callno.

    // AKA we can clobber noreturn syscalls with others
    // and catch the results,

      if (likely(!(IS_NORETURN_SC(sysc->callno) /*|| \
              sysc->callno == __NR_fork || \
              sysc->callno == __NR_clone)*/))) {
        //printf("Clobbering scratch regs for %lu\n", sysc->callno);
        // If it's a noreturn, fork or clone, we can't do this. Probably clone3 too?
        set_magic_values = true;
        //r.rflags = (r.rflags & ~0x2); // Unset bit 1 (valid)
        r.r14 = R14_INJECTED;
        r.r15 = (uint64_t)details;

        if (sysc->callno == __NR_clone || \
            sysc->callno == __NR_fork || \
            sysc->callno == __NR_vfork) {
          // Double return. All of these return 0 in parent, nonzero in child. Neg on error
          double_return_parents.insert(details);
          double_return_children.insert(details);
        }
      }

    assert(setregs(cpu, &r) == 0);
    return set_magic_values;
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

syscall_context* find_and_init_coopter(void* cpu, unsigned long cpu_id, unsigned long fs, int callno, unsigned long asid, unsigned long pc) {
  syscall_context *details = NULL;
  for (const auto &pair : coopters) { // For each coopter, see if it's interested. First to return non-null wins
    if (pending_exits.contains(pair.first)) {
      //printf("Skipping coopter %s because we're waiting to unload it\n", pair.first.c_str());
      continue;
    }

    coopter_f* coopter = pair.second;
    create_coopt_t *f = (*coopter)(cpu, callno, pc, asid);
    // if a should_coopt function returns non-null, set this asid up to be coopted
    // by the coopter generator which it returned.
    if (f == NULL) {
      //printf("Should coopt for %d returns NULL\n", callno);
      continue;
    }

    hyde_printf("[CREATE coopter for %s in %lx on cpu %ld before syscall %d at %lx]\n", pair.first.c_str(), asid, cpu_id, callno, pc);

    // Get & store original registers before we run the coopter's first iteration
    details = new syscall_context {
      .cpu = cpu,
      .child = false,
      .asid = asid,
      .use_orig_regs = false,
      .custom_return = 0,
    };

    // Read guest regs from KVM
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &details->orig_regs) == 0); //dump_regs(r);

    // Create original syscall using info from regs
    details->orig_syscall = new hsyscall {
        .callno = get_arg(details->orig_regs, RegIndex::CALLNO),
        .nargs = 6,
        .has_retval = false,
    };

    // Set args using info from regs
    for (int i = 0; i < 6; i++) {
      details->orig_syscall->args[i].value = get_arg(details->orig_regs, (RegIndex)i);
      details->orig_syscall->args[i].is_ptr = false;
    }

    coopted_procs.insert(details);

    // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
    // The value we get in rflags won't match the value that emulate_syscall is putting
    // into rflags - so we compute it ourselves
    //a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;
    // XXX: Why don't we need/want that anymore?

    // XXX: this *runs* the coopter function up until its first co_yield/co_ret
    details->coopter = (*f)(details).h_;
    details->name = pair.first;
    return details;
  }

  return NULL;
}

#ifdef DEBUG_LOG
static bool file_open = false;
static std::ofstream f;
#endif

void on_syscall(void *cpu, unsigned long cpu_id, unsigned long fs, long unsigned int callno, long unsigned int asid, long unsigned int pc,
                           long unsigned int orig_rcx, long unsigned int orig_r11, long unsigned int r14, long unsigned int r15) {
#ifdef DEBUG_LOG
  // Log, don't co-opt
  if (!file_open) {
	  f.open("/tmp/trace.txt", std::ios::out);
	  file_open = true;
  }
  f << "syscall " << std::hex << asid << " cpu " << cpu_id << " callno " << callno << ", pc " << pc << " rsp " << rsp << " fs " << fs << std::endl;
  return;
#endif

  syscall_context *target_details = NULL;
  bool first = false;

  // Ignore sigreturn, track seccomp for this asid (and ignore if it's seccomp'd)
  if (unlikely(!is_syscall_targetable(callno, asid))) {
    return;
  }

  // On syscall: If previously-coopted, we'll have magic value in r14
  // and pointer to coopter state in r15

  if (unlikely(r14 == R14_INJECTED)) {
    target_details = (syscall_context*)r15;
    hyde_printf("Load old coopter for %lx at callno %lu from %p\n", asid, callno, target_details);
  } else if ((target_details = find_and_init_coopter(cpu, cpu_id, fs, callno, asid, (unsigned long)pc))) {
    hyde_printf("Created new coopter for %lx at callno %lu: %p\n", asid, callno, target_details);

    first = true;
    target_details->orig_rcx = orig_rcx; // These get clobbered by the syscall instruction
    target_details->orig_r11 = orig_r11; // so we need to hold on to them
  } else {
    // No existing coopter, no created co-opter - nothing to do
    return;
  }

  // In general, we'll store the original syscall and require the *user*
  // to run it when they want it to happen (e.g., start or end)
  // Original syscall will be mutable.

  hsyscall sysc;
  auto &promise = target_details->coopter.promise();

  if (likely(!target_details->coopter.done())) {
    // We have something to inject, i't stored in the promise value
    sysc = promise.value_;
    hyde_printf("have syscall to inject: replace %lu with %lu\n", target_details->orig_syscall->callno, sysc.callno);

  } else if (unlikely(first)) {
    // Nothing to inject and this is the first syscall
    // so we need to run a skip! We do this with a "no-op" syscall
    // and hiding the result on return

    if (!target_details->orig_syscall->has_retval) {
      // No-op: user registered a co-opter but it did nothing so we're already done
      // The user didn't run the original syscall, nor did they set a return value.
      // This means the guest is going to see the original callno as a result.
      // This is probably a user error - warn about it.
      printf("USER ERROR in %s: co-opter ran 0 syscalls (not even original) and left result unspecified.\n", target_details->name.c_str());
      target_details->coopter.destroy();

      // Remove target_details from oru coopted_procs set
      coopted_procs.erase(target_details);
      delete target_details->orig_syscall;
      delete target_details;
      return;
    }

    // We have a return value specified - run the skip syscall
    // and on return, set the return value to the one specified
    sysc = {
      .callno = SKIP_SYSNO,
      .nargs = 0,
      .retval = target_details->orig_syscall->retval,
      .has_retval = true
    };
    hyde_printf("skip original (%ld) replace with %ld and set RV to %lx\n", target_details->orig_syscall->callno, sysc.callno, target_details->orig_syscall->retval);

  } else {
    assert(0 && "FATAL: Injecting syscall, but from a previously-created co-routine that is done\n");
  }

  // We now have a syscall in sysc yielded from a coopter. It's safe so assume it will almost always be different.
  // So let's set the guest CPU state to the syscall we want to inject. Even if this is the original syscall,
  // we need to restore registers to get the right syscall number in place of the last return value.

  if (!set_regs_to_syscall(target_details, cpu, &sysc)) {
    // If it's a noreturn SC, we can't catch it later, clean up now
    target_details->coopter.destroy();
    delete target_details->orig_syscall;
    coopted_procs.erase(target_details);
    delete target_details;
  }
}

void on_sysret(void *cpu, unsigned long cpu_id, unsigned long fs, long unsigned int retval, long unsigned int asid, long unsigned int pc, long unsigned int r14, long unsigned int r15) {

  if (unlikely(r14 != R14_INJECTED)) {
    // Not an injected syscall, leave it alone. Note KVM shouldn't even call on_sysret in this case.
    printf("Warning: sysret from non-injected syscall\n");
    return;
  }

  // XXX if we ever get this wrong, we'll crash!
  // Should we have a 2nd register other than r15 to validate? Ideally
  // something the guest can't ever set normally.
  syscall_context *details = (syscall_context*)r15;

  bool has_parent = double_return_parents.count(details);
  bool has_child = double_return_children.count(details);

  if (has_parent) {
    // Parent gets negative error or child PID
    if (retval != 0) {
      // This is the parent
      double_return_parents.erase(details);
      if ((long signed int)retval < 0) {
        // ...and the parent failed - don't wait for the child
        double_return_children.erase(details);
      } else {
        // Parent was successful and returns first
        if (has_child) {
          // Duplicate details in parent so child has its own
          memcpy(details, &r15, sizeof(syscall_context));
        }
      }
    }
  }

  if (has_child) {
    // Child gets return value of 0
    if (retval == 0) {
      double_return_children.erase(details);
      details->child = true;
      
      if (has_parent) {
        // Child returns first - duplicate details
        // so parent has its own
        memcpy(details, &r15, sizeof(syscall_context));
      }
    }
  }

  //hyde_printf("Sysret from %s after callno %lu\n", details->name.c_str(), details->orig_syscall->callno);

#ifdef DEBUG_LOG
  // XXX: SLOW, DEBUGGING - AH ha, sregs.fs.base can distinguish between threads with same asid!
  if (!file_open) {
	  f.open("/tmp/trace.txt", std::ios::out);
	  file_open = true;
  }
  f << "sysret " << std::hex << asid << " cpu " << cpu_id << " to pc " << pc << " rsp " << rsp << " fs " << fs << std::endl;
  return;
#endif

  hyde_printf("\tAfter injected sc in %lx: ", asid);
  // If hyde program wants to finish and set a retval without running another
  // syscall, it can set orig_syscall->retval and orig_syscall->has_retval
  // Then we'll just set this to the retval on the sysret
  if (unlikely(details->orig_syscall->has_retval)) {
    hyde_printf("Did nop (really %lu) with rv=%lx.", details->orig_syscall->callno, retval);
  } else {
    details->last_sc_retval = (uint64_t)retval;
    hyde_printf("rv=%lx.", retval);
  }
  // If we set has_retval, it's in a funky state - we need to advance it so it will finish, otherwise we'll
  // keep yielding the last (no-op) syscall over and over again
  details->coopter(); // Advance - will have access to the just returned value

  struct kvm_regs new_regs = details->orig_regs;

  if (!details->coopter.done()) {
    // We have more to do, re-execute the syscall instruction, which will hit on_syscall and then this fn again.
    hyde_printf("Not done, go back to %lx\n", pc-2);
    new_regs.rip = pc-2; // Take it back now, y'all

    // eflags: unset bit 1 (invalid), r14 contains magic, r15 contains pointer
    //new_regs.rflags = (new_regs.rflags & ~0x2) | 0x2; // Unset bit 1 (invalid)
    new_regs.r14 = R14_INJECTED;
    new_regs.r15 = (uint64_t)details;

    assert(setregs(cpu, &new_regs) == 0);
    return;
  }

  // All done - clean up time. Get result, examine to decide if we should disable this hyde program
  // or print a warning or just keep chugging along. At end of each coopter, we check if any hyde
  // programs can (now) be safely unloaded that previously wanted to unload.

  // If we're done, we have to restore rflags, r14, and r15. But we already have
  // those unclobbered values in new_regs from details->orig_regs!

  // Get result
  auto &promise = details->coopter.promise();
  ExitStatus result = promise.retval;

  struct kvm_regs regs_on_ret2;
#ifdef HYDE_DEBUG
  getregs(details, &regs_on_ret2);
  hyde_printf("Done, contine after sc to %lx. ", pc);
#endif

  // XXX TESTING ONLY
  //getregs(details, &regs_on_ret2);
  //assert((regs_on_ret2.rflags & 0x2) == 0);


  if (details->orig_syscall->has_retval) {
    // A user set a retval in orig_syscall object, return that
    // This is how we'd do INJECT_SC_A, ORIG_SC, INJECT_SC_B and
    // pretend nothing was injected
    new_regs.rax = details->orig_syscall->retval;
    hyde_printf("change return to be %lx\n", details->orig_syscall->retval);
  } else {
    // We weren't told the orig_syscall has a retval, that means the last
    // return value should be what we pass back. This is how we'd do
    // INJECT_SC_A, INJECT_SC_B, ORIG.
    getregs(details, &regs_on_ret2);
    new_regs.rax = regs_on_ret2.rax;
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

  hyde_printf("\n");

  // Remove this active coopter
  std::string name = details->name;

  details->coopter.destroy();
  delete details->orig_syscall;
  coopted_procs.erase(details);
  delete details;

  // Based on result, update state for the whole hyde program
  switch (result) {
    case ExitStatus::FATAL:
      printf("[HyDE] Fatal error in %s\n", name.c_str());
      [[fallthrough]]; // Fancy C++ism to fix compiler warning about falling through
    case ExitStatus::FINISHED:
      if (!pending_exits.contains(name)) {
        printf("[HyDE] Unloading %s on cpu %d\n", name.c_str(), 0);
        //try_unload_coopter(details->name, cpu, 0); // XXX multicore guests, need to do for all CPUs?
        pending_exits.insert(name);
      }
      break;

    case ExitStatus::SINGLE_FAILURE:
      printf("[HyDE] Warning %s experienced a non-fatal failure\n", name.c_str());
      break;

    case ExitStatus::SUCCESS:
      // Nothing to do
      break;
  }

  // For each pending exit (i.e., coopter that is done), check if any of the injections we're tracking are it
  for (auto it = pending_exits.begin(); it != pending_exits.end(); ) {
    // Check if any coopters are still active
    bool active = false;
    for (const auto &kv : coopted_procs) {
      if (kv->name == *it) {
        active = true;
        break;
      }
    }

    if (!active) {
      if (try_unload_coopter(*it, cpu, 0)) { // Safe to unload now
        printf("[HyDE] Unloaded %s\n", it->c_str());
        //it = std::erase_if(pending_exits, [&](const auto& name) { return name == *it; });
        //it = std::remove_if(pending_exits.begin(), pending_exits.end(), [&](const auto& name) { return name == *it; });
        it = pending_exits.erase(it);
        continue;
      } else {
        printf("ERROR erasing %s\n", it->c_str());
      }
    }
    ++it;
  }

  assert(setregs(cpu, &new_regs) == 0);
}