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
#include <type_traits>
#include <unistd.h>
#include <sys/syscall.h>

#include "qemu/compiler.h"
#include "exec/hwaddr.h" // for hwaddr typedef
//#include "accel/kvm/kvm-cpus.h" // for kvm_host_addr_from_physical_memory
extern "C" int kvm_host_addr_from_physical_memory(hwaddr gpa, hwaddr *phys_addr);

#include "hyde_common.h"
#include "hyde_internal.h"

std::set<std::string> pending_exits = {};

void dprintf(const char *fmt, ...) {
#ifdef HYDE_DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
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
    coopters.erase(it++);
  }

  disable_syscall_introspection(cpu);
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

// special regs
int getsregs(void *cpu, struct kvm_sregs *sregs) {
  return kvm_vcpu_ioctl(cpu, KVM_GET_SREGS, sregs);
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

asid_details* find_and_init_coopter(void* cpu, unsigned long cpu_id, unsigned long fs, int callno, unsigned long asid, unsigned long pc) {
  asid_details *a = NULL;
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
      return NULL; // XXX: should this be a continue?
    }

    //printf("[CREATE coopter for %s in %lx on cpu %ld before syscall %d at %lx]\n", pair.first.c_str(), asid, cpu_id, callno, pc);

    // Get & store original registers before we run the coopter's first iteration
    a = new asid_details {
      .cpu = cpu,
      .asid = asid,
      .use_orig_regs = false,
      .custom_return = 0,
    };

    // Read guest regs from KVM
    assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &a->orig_regs) == 0); //dump_regs(r);

    // Create original syscall using info from regs
    a->orig_syscall = new hsyscall {
        .callno = get_arg(a->orig_regs, RegIndex::CALLNO),
        .nargs = 6,
        .has_retval = false,
    };

    // Set args using info from regs
    for (int i = 0; i < 6; i++) {
      a->orig_syscall->args[i].value = get_arg(a->orig_regs, (RegIndex)i);
      a->orig_syscall->args[i].is_ptr = false;
    }

    active_details[{asid, cpu_id, fs}] = a;

    // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
    // The value we get in rflags won't match the value that emulate_syscall is putting
    // into rflags - so we compute it ourselves
    //a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;
    // XXX: Why don't we need/want that anymore?

    // XXX: this *runs* the coopter function up until its first co_yield/co_ret
    a->coopter = (*f)(active_details[{asid, cpu_id, fs}]).h_;
    a->name = pair.first;
    return a;
  }

  return NULL;
}

void on_syscall(void *cpu, unsigned long cpu_id, unsigned long fs, long unsigned int callno, long unsigned int asid, long unsigned int pc,
                           long unsigned int orig_rcx, long unsigned int orig_r11, long unsigned int rsp) {
  asid_details *a = NULL;
  bool first = false;

  //printf("syscall %lx cpu %lu callno %lu, pc %lx, rsp %lx fs %lx\n", asid, cpu_id, callno, pc, rsp, fs);

  if (unlikely(!is_syscall_targetable(callno, asid))) {
    return;
  }

  if (likely(!active_details.contains({asid, cpu_id, fs}))) {
    // No active co-opter for asid - check to see if any want to start
    // If we find one, we initialize it, running to the first yield/ret
    // We won't launch a new co-opter if it's trying to unload

    #if 0
    // XXX DEBUG: sanity check - do we have asid, cpu_id with a different fs already?
    for (const auto &pair : active_details) { // For each coopter, see if it's interested. First to return non-null wins
      if (std::get<0>(pair.first) == asid && std::get<1>(pair.first) == cpu_id) {
        printf("AH ha, multiple FS for same asid/cpu pair! %lx, %lx: %lx vs %lx\n", asid, cpu_id, fs, std::get<2>(pair.first));
      }
    }
    #endif


    a = find_and_init_coopter(cpu, cpu_id, fs, callno, asid, (unsigned long)pc);
    if (likely(a == NULL)) {
      return; 
    }
    a->orig_rcx = orig_rcx;
    a->orig_r11 = orig_r11;

    first = true;
    //dprintf("New coopter in {%lx, %lx} at %lx: ", asid, cpu_id, pc);
    //printf("New coopter from %s to run before %ld in {%lx, %lx} at %lx\n", a->name.c_str(), callno, asid, cpu_id, pc);
  } else {
    // We already have a co-opter for this asid, it should have been
    // advanced on the last syscall return
    dprintf("Existing coopter in {%lx, %lx} at %lx: ", asid, cpu_id, pc);
    a = active_details.at({asid, cpu_id, fs});
  }

  //printf("Syscall in active %lx on cpu %ld: callno: %ld\n", asid, cpu_id, callno);

  // In general, we'll store the original syscall and require the *user*
  // to run it when they want it to happen (e.g., start or end)
  // Original syscall will be mutable.

  hsyscall sysc;
  sysc.nargs = (unsigned int)-1;
  auto &promise = a->coopter.promise();

  if (likely(!a->coopter.done())) {
    // We have something to inject
    sysc = promise.value_;
    dprintf("have syscall to inject: %lu\n", sysc.callno);

  } else if (unlikely(first)) {
    // Nothing to inject and this is the first syscall
    // so we need to run a skip! We do this with a "no-op" syscall
    // and hiding the result on return

    if (!a->orig_syscall->has_retval) {
      // No-op: user registered a co-opter but it did nothing so we're already done
      // The user didn't run the original syscall, nor did they set a return value.
      // This means the guest is going to see the original callno as a result.
      // This is probably a user error - warn about it.
      printf("USER ERROR in %s: co-opter ran 0 syscalls (not even original) and left result unspecified.\n", a->name.c_str());
      a->coopter.destroy();
      active_details.erase({asid, cpu_id, fs});
      return;
    }

    // We have a return value specified - run the skip syscall
    // and on return, set the return value to the one specified

    sysc.nargs = 0;
    sysc.callno = SKIP_SYSNO;
    sysc.has_retval = true;
    sysc.retval = a->orig_syscall->retval;
    dprintf("skip original (%ld) replace with %ld and set RV to %lx\n", a->orig_syscall->callno, sysc.callno, a->orig_syscall->retval);

  } else {
    // Unreachable.
    assert(0 && "FATAL: Injecting syscall, but from a previously-created co-routine that is done\n");
    // This should never happen - if it isn't the first one
    // we would have bailed on the last return if we didn't have more
    return;
  }

  // We now have a syscall in sysc yielded from a coopter. It's safe so assume it will almost always be different.
  // So let's set the guest CPU state to the syscall we want to inject. Even if this is the original syscall,
  // we need to restore registers to get the right syscall number in place of the last return value.
  set_regs_to_syscall(a, cpu, &sysc, &a->orig_regs);

  // If the injected syscall won't return to the next PC the same ASID after this syscall, we can't catch it.
  // This happens if the process is exiting, or if it jumps control flow to somwhere else (i.e., execve)
  // There are two implications for this:
  //  1) We can't clean up our state for this coroutine on the return
  //  2) The user can't run more syscalls in this coroutine

  // As such, we clean up *here*, but we also detect if the coroutine is still alive and warn in that case.
  if (unlikely(sysc.callno == __NR_execve || \
               sysc.callno == __NR_execveat || \
               sysc.callno == __NR_exit || \
               sysc.callno == __NR_exit_group)) {
    // Hmm, this co-routine isn't run again until the on sysret. It might be dangerous to explicitly run it here, but YOLO

    // Pretend we did run it and got a result for the sake of the co-routine which could still (incorrectly) use this value.
    // This is a bit tricky. We can either falsely advance the coopter with an unset retval (!!) here in order to see if it's
    // going to try injecting more syscalls and conditionally warn. Or we can not advance it and never warn. We pick the former.

    // Hmm, running th coopter willy-nilly was a bad idea. Let's not do that

    //a->coopter(); // Advance the coroutine such that it will finish, assuming it had no more syscalls to yield.
    //if (!a->coopter.done()) {
      //printf("USER ERROR in %s: co-opter runs non-returning syscall %lu but it wasn't the last syscall in the co-opter. Subsequent logic in co-opter will not run\n", a->name.c_str(), sysc.callno);
    //}
    a->coopter.destroy();
    delete a->orig_syscall;
    delete a;
    active_details.erase({asid, cpu_id, fs});
  }
}

void on_sysret(void *cpu, unsigned long cpu_id, unsigned long fs, long unsigned int retval, long unsigned int asid, long unsigned int pc, long unsigned int rsp) {

  // XXX: SLOW, DEBUGGING - AH ha, sregs.fs.base can distinguish between threads with same asid!
  //printf("sysret %lx cpu %lu to pc %lx rsp %lx fs %lx\n", asid, cpu_id, pc, rsp, fs);

  auto iter = active_details.find({asid, cpu_id, fs});
  if (likely(iter == active_details.end())) {
    // We don't have a coopter for this asid, so will leave it alone
    return;
  }

  asid_details *details = iter->second;

  dprintf("\tAfter injected sc in %lx:", asid);
  // If hyde program wants to finish and set a retval without running another
  // syscall, it can set orig_syscall->retval and orig_syscall->has_retval
  // Then we'll just set this to the retval on the sysret
  if (unlikely(details->orig_syscall->has_retval)) {
    dprintf("Did nop (really %lu) with rv=%lx.", details->orig_syscall->callno, retval);
  } else {
    details->last_sc_retval = (uint64_t)retval;
    dprintf("rv=%lx.", retval);
  }
  // If we set has_retval, it's in a funky state - we need to advance it so it will finish, otherwise we'll
  // keep yielding the last (no-op) syscall over and over again
  details->coopter(); // Advance - will have access to the just returned value

  struct kvm_regs new_regs;
  memcpy(&new_regs, &details->orig_regs, sizeof(struct kvm_regs));

  //printf("Done is %d\n", details->coopter.done());

  if (!details->coopter.done()) {
    // We have more to do, re-execute the syscall instruction, which will hit on_syscall and then this fn again.
    dprintf("Not done, go back to %lx\n", pc-2);
    new_regs.rip = pc-2; // Take it back now, y'all
    assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &new_regs) == 0);
    return;
  }

  // All done - clean up time. Get result, examine to decide if we should disable this hyde program
  // or print a warning or just keep chugging along. At end of each coopter, we check if any hyde
  // programs can (now) be safely unloaded that previously wanted to unload.

  // Get result
  auto &promise = details->coopter.promise();
  ExitStatus result = promise.retval;

  struct kvm_regs oldregs;
#ifdef HYDE_DEBUG
  getregs(details, &oldregs);
  dprintf("Done, return to %lx. ", pc); 
#endif


  if (details->orig_syscall->has_retval) {
    // We set a retval in orig_syscall object, return that
    // This is how we'd do INJECT_SC_A, ORIG_SC, INJECT_SC_B and
    // pretend nothing was injected
    new_regs.rax = details->orig_syscall->retval;
    dprintf("change return to be %lx\n", details->orig_syscall->retval);
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

  dprintf("\n");

  // Remove this active coopter
  std::string name = details->name;

  details->coopter.destroy();
  delete details->orig_syscall;
  delete details;
  active_details.erase({asid, cpu_id, fs});

  // Based on result, update state for the whole hyde program
  switch (result) {
    case ExitStatus::FATAL:
      printf("[HyDE] Fatal error in %s\n", name.c_str());
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
    for (const auto &kv : active_details) {
      if (kv.second->name == *it) {
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
  assert(kvm_vcpu_ioctl(cpu, KVM_SET_REGS, &new_regs) == 0);
}
