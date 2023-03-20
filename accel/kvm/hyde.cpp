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

// TODO: make more helpers generators so they can inject syscalls

// We should get rid of these...
__u64 memread(asid_details*, __u64, hsyscall*);
__u64 translate(void *cpu, __u64 gva, int* status);


// TODO: Make this a coroutine so we can yield and wait for a syscall to complete
// if necessary. - then we can use ga_helpers to access stack based arguments
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
        .callno = CALLNO(r),
        .nargs = 6,
        .args = { ARG0(r), ARG1(r), ARG2(r), ARG3(r), ARG4(r), ARG5(r) },
        .has_retval = false,
      },
      .cpu = cpu,
      .asid = asid,
      .use_orig_regs = false,
      .custom_return = 0,
    };

    memcpy(&a->orig_regs, &r, sizeof(struct kvm_regs));

    // This ends our maybe race condition - we've built the asid_details entry
    active_details[{asid, cpu_id}] = a;

    dprintf("Co-opter starts from: ");
    dump_syscall(*a->orig_syscall);

    // XXX CPU masks rflags with these bits, but it's not shown yet in KVM_GET_REGS -> rflags!
    // The value we get in rflags won't match the value that emulate_syscall is putting
    // into rflags - so we compute it ourselves
    //a->orig_regs.rflags = (a->orig_regs.r11 & 0x3c7fd7) | 0x2;
    // XXX: Why don't we need/want that anymore?

    // XXX: this *runs* the coopter function up until its first co_yield/co_ret
    a->coopter = (*f)(active_details[{asid, cpu_id}]).h_;
    return a;
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
    dprintf("\n***Return from no-op (er, actually %lu) SC in %lx with rv=%lx\n", details->orig_syscall->callno, asid, retval);
  } else {
    details->last_sc_retval = retval;
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

    details->coopter.destroy();
    active_details.erase({asid, cpu_id});
  } else {
    //assert(!details->coopter.promise().did_return);
    dprintf("Not done in %lx, %ld - go back to %lx\n", asid, cpu_id, pc-1);
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
#if 0
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
#endif

// NARGS macro from https://stackoverflow.com/a/33349105/2796854
#define NARGS(...) std::tuple_size<decltype(std::make_tuple(__VA_ARGS__))>::value



#if 0
// yield and build syscall don't take number of arguments, we calculate at compile time
#define build_syscall(h, callno, ...)  (_build_syscall(h, callno, NARGS(__VA_ARGS__), __VA_ARGS__))
//#define yield_syscall(r, callno, ...) (build_syscall(&r->scratch, callno, __VA_ARGS__), (co_yield r->scratch), r->retval)

/* Yield_syscall yields a syscall, then gets retval after it's set on sysret in our asid_details */
#define yield_syscall(r, callno, ...) \
({ \
  _build_syscall(&r->scratch, callno, NARGS(__VA_ARGS__) __VA_OPT__(,) __VA_ARGS__, NULL); \
  (co_yield r->scratch); \
  r->last_sc_retval; \
})
#endif

void _build_syscall(hsyscall* s, uint callno, int nargs, ...) {
  s->callno = callno;
  s->nargs = nargs;
  // for each va arg
  va_list args;
  va_start(args, nargs);
  for (int i = 0; i < nargs; i++) {
    s->args[i] = va_arg(args, uint64_t);
  }
  va_end(args);
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


__u64 memread(asid_details* r, __u64 gva, hsyscall* sc) {
  printf("DEPRECATED: memread(gva=%llx, sc=%p)\n", gva, sc);
  return (__u64)-1;
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

bool can_translate_gva(void*cpu, ga* gva) {
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
bool translate_gva(asid_details *r, ga* gva, uint64_t* hva) {
  if (!can_translate_gva(r->cpu, gva)) {
    return false;
  }
  // Duplicate some logic from can_translate_gva so we can get the physaddr here
  struct kvm_translation trans = { .linear_address = (__u64)gva };
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, (__u64*)hva) == 1);
  return true;
}

/*
 * Copy size bytes from a guest virtual address into a host buffer.
 */
SyscCoro ga_memcpy_one(asid_details* r, void* out, ga* gva, size_t size) {
  // We wish to read size bytes from the guest virtual address space
  // and store them in the buffer pointed to by out. If out is NULL,
  // we allocate it

  uint64_t hva = 0;

  if (!translate_gva(r, gva, &hva)) {
      yield_syscall(r, access, (__u64)gva, 0);
      if (!translate_gva(r, gva, &hva)) {
        yield_syscall(r, access, (__u64)gva, 0); // Try again
        if (!translate_gva(r, gva, &hva)) {
          co_return -1; // Failure, even after two retries?
        }
      }
  }

  //printf("Writing %lu bytes of data to %lx - %lx\n",  size, (uint64_t)out, (uint64_t)out + size);
  memcpy((uint64_t*)out, (void*)hva, size);
  co_return 0;
}


#define PAGE_SIZE 1024
/* Memread will copy guest data to a host buffer, paging in memory as needed.
 * It's an alias for ga_memcpy but that might go away later in favor of this name.
 */
SyscCoro ga_memread(asid_details* r, void* out, ga* gva_base, size_t size) {
  co_return yield_from(ga_memcpy, r, out, gva_base, size);
}

/*
 * Copy size bytes from a guest virtual address into a host buffer, re-issue
 * translation requests as necessary, guaranteed to work so long as address through
 * address + size are mappable
 */
SyscCoro ga_memcpy(asid_details* r, void* out, ga* gva_base, size_t size) {

  ga* gva_end = (ga*)((uint64_t)gva_base + size);
  uint64_t gva_start_page = (uint64_t)gva_base  & ~(PAGE_SIZE - 1);
  //uint64_t gva_end_page = (uint64_t)gva_end  & ~(PAGE_SIZE - 1);
  uint64_t first_page_size = std::min((uint64_t)gva_base - gva_start_page, (uint64_t)size);

  // Copy first page up to alignment (or maybe even end!)
  //printf("Read up to %lu bytes into hva %lx from gva %lx\n", first_page_size, (uint64_t)out, (uint64_t)gva_base);
  if (yield_from(ga_memcpy_one, r, out, gva_base, first_page_size) == -1) {
    printf("First page read fails\n");
    co_return -1;
  }

  gva_base += first_page_size;
  out = (void*)((uint64_t)out + first_page_size);

  while ((uint64_t)gva_base < (uint64_t)gva_end) {
    uint64_t this_sz = std::min((uint64_t)PAGE_SIZE, (uint64_t)gva_end - (uint64_t)gva_base);
      //printf("SUBSEQUENT read (Still need %lx bytes) up to %lu bytes into hva %lx from gva %lx\n",
      //(uint64_t)gva_end - (uint64_t)gva_base, this_sz, (uint64_t)out, (uint64_t)gva_base);

    if (yield_from(ga_memcpy_one, r, out, gva_base, this_sz) == -1) {
    printf("Subsequent page read fails\n");
      co_return -1;
    }
    gva_base += this_sz;
    out = (void*)((uint64_t)out + this_sz);
  }
  co_return 0;

  #if 0
  // Let's read from address to next page, then read pages? This is still a bit of a lazy implementation,
  // really we should be like binary searching


  // Given address X that lies somewhere between two pages, and say we want the subsequent page:
  // | page1 start     X      | page2 start     | page 3 start

  // First we calculate page1 start, translate it, calculate the offset of X into page one
  // and copy the number of bytes from X to the end of page 1 into the buffer

  #define PAGE_SIZE 0x1000uL
  uint64_t start_offset = (uint64_t)gva_base & (PAGE_SIZE-1);
  ga* first_page = (ga*)((uint64_t)gva_base & ~(PAGE_SIZE-1));

  if (first_page != gva_base) {
    // Original address wasn't page aligned
    uint64_t hva;
    if (!translate_gva(r, first_page, &hva)) {
        yield_syscall(r, __NR_access, (__u64)first_page, 0);
        if (!translate_gva(r, gva_base, &hva)) {
          co_return -1; // Failure, even after retry
        }
    }
    // Sanity check, should be able to translate requested address now that we have the page?
    assert(can_translate_gva(r->cpu, gva_base));

    //printf("\tga_memcpy: first copy. guest first page %lx maps to host %lx, reading from host at %lx\n", (uint64_t)first_page, hva, hva + start_offset);
    memcpy((uint64_t*)out, (void*)(hva + start_offset), std::min((ulong)size, (ulong)(PAGE_SIZE - start_offset)));
  }

  // Now copy page-aligned memory, one page at a time
  for (ga* page = gva_base + start_offset; page < gva_base + size; page += PAGE_SIZE) {
    ulong remsize  = std::min((ulong)PAGE_SIZE, (ulong)((gva_base + size) - page));

    printf("\tga_memcpy: subsequent page = %p, size=%lu\n", page, remsize);
    uint64_t hva;
    if (!translate_gva(r, page, &hva)) {
        yield_syscall(r, __NR_access, (__u64)page, 0);
        if (!translate_gva(r, gva_base, &hva)) {
          co_return -1; // Failure, even after retry
        }
    }

    printf("\tga_memcpy: subsequent copy of %lu bytes from %lx to %lx\n", remsize, hva, (uint64_t)out+(page-gva_base));
    memcpy((uint64_t*)out+(page-gva_base), (void*)hva, remsize);
  }

  co_return 0;
  #endif
}

/* Given a host buffer, write it to a guest virtual address. The opposite
 * of ga_memcpy */
SyscCoro ga_memwrite(asid_details* r, ga* gva, void* in, size_t size) {
  // TODO: re-issue translation requests as necessary
  uint64_t hva;
  assert(size != 0);

  if (!translate_gva(r, gva, &hva)) {
      //yield_syscall(r, __NR_access, (__u64)gva, 0);
      yield_syscall(r, access, (__u64)gva, 0);
      if (!translate_gva(r, gva, &hva)) {
        co_return -1; // Failure, even after retry
      }
  }

  //printf("Copying %lu bytes of %s to GVA %lx\n", size, (char*)in, (uint64_t)gva);
  memcpy((uint64_t*)hva, in, size);
  co_return 0;
}

SyscCoro ga_map(asid_details* r,  ga* gva, void** host, size_t min_size) {
  // Set host to a host virtual address that maps to the guest virtual address gva

  // TODO: Assert that gva+0 and gva+min_size can both be reached
  //at host[0], and host[min_size] after mapping. If not, fail?
  // TODO how to handle failures here?
  __u64 _gva = (uint64_t)gva & (uint64_t)-1;

  struct kvm_translation trans = { .linear_address = _gva };
  assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);

  // Translation failed on base address - not in our TLB, maybe paged out
  if (trans.physical_address == (unsigned long)-1) {
      yield_syscall(r, access, _gva, 0);

      // Now retry. if we fail again, bail
      //printf("Retrying to read %llx\n", trans.linear_address);
      assert(kvm_vcpu_ioctl(r->cpu, KVM_TRANSLATE, &trans) == 0);
      //printf("\t result: %llx\n", trans.physical_address);
      if (trans.physical_address == (unsigned long)-1) {
        printf("Oh no we double fail mapping %llx\n", _gva);
        co_return -1; // Failure!
      }
  }

  // Translation has succeeded, we have the guest physical address
  // Now translate that to the host virtual address
  __u64 hva;
  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &hva) == 1);
  (*host) = (void*)hva;

  co_return 0;
}

// Helpers
void dump_sc(struct kvm_regs r) {
#ifndef WINDOWS
  // LINUX
  printf("Callno %lld (%llx, %llx, %llx, %llx, %llx, %llx)\n", CALLNO(r),
        ARG0(r), ARG1(r), ARG2(r), ARG3(r), ARG4(r), ARG5(r));
#else
  // Windows
  printf("Callno %lld (%llx, %llx, %llx, %llx)\n", CALLNO(r),
        r.r10, r.rdx, r.r8, r.r9);
#endif
}

void dump_sc_with_stack(asid_details* a, struct kvm_regs r) {
  dump_sc(r);
  // Dump stack too!
  unsigned long int *stack;
  stack = (unsigned long int*)memread(a, r.rsp, nullptr);
#ifdef WINDOWS
  for (int i=0; i < 10; i++) {
#else
    if (0) { // TODO linux stack based logging
      int i = 0;
#endif
    printf("\t - Stack[%d] = %lx\n", i, stack[i]);
  }
}

void dump_regs(struct kvm_regs r) {
  printf("PC: %016llx    RAX: %016llx    RBX %016llx    RCX %016llx    RDX %016llx   RSI %016llx   RDI %016llx   RSP %016llx\n",
      r.rip, r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rsp);
  printf("\t RBP: %016llx    R8 %016llx    R9 %016llx    R10 %016llx    R11 %016llx    R12 %016llx    R13 %016llx\n", r.rbp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13);
  printf("\t R14: %016llx    R15: %016llx    RFLAGS %016llx\n", r.r14, r.r15, r.rflags);
}

void dump_syscall(hsyscall h) {
#ifdef DEBUG
  printf("syscall_%d(", h.callno);
  for (size_t i=0; i < h.nargs; i++) {
    printf("%#lx", h.args[i]);
    if ((i+1) < h.nargs) printf(", ");
  }
  printf(")\n");
#endif
}

#if 0
strace -e execve -e raw=execve ./a.out ^C
root@ubuntu:~# cat foo.c 
#include <stdio.h>

int main(int argc, char** argv, char** environ) {
        printf("environ starting at %p\n", environ);
        while (*environ != NULL) {
                printf("\tAt %p we have %s\n", environ, *environ);
                ++environ;
        }
}

#endif