#ifndef HYDE_H
#define HYDE_H

#include <coroutine>
#include <exception>
#include <iostream>

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);
extern "C" int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);

//RDI, RDX, R10, R8, R9
#define CALLNO(s) s.rax
#define ARG0(s) s.rdi
#define ARG1(s) s.rdx
#define ARG2(s) s.rsi
#define ARG3(s) s.r10
#define ARG4(s) s.r8
#define ARG5(s) s.r9

#define set_CALLNO(s, x) s.rax =x
#define set_ARG0(s, x) s.rdi =x
#define set_ARG1(s, x) s.rsi =x
#define set_ARG2(s, x) s.rdx =x
#define set_ARG3(s, x) s.r10 =x
#define set_ARG4(s, x) s.r8  =x
#define set_ARG5(s, x) s.r9  =x

#define GETREGS(r, regs) assert(kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, &regs) == 0);

typedef struct {
  unsigned int callno;
  unsigned long args[6];
  unsigned int nargs;
} syscall;
 
// Co-routine classes based off https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
struct SyscCoRoutine {
  struct promise_type {
    syscall value_;

    ~promise_type() { }

    SyscCoRoutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}
    std::suspend_always yield_value(syscall value) {
      value_ = value;
      return {};
    }
    void return_void() {}

  };

  std::coroutine_handle<promise_type> h_;
};

typedef std::coroutine_handle<SyscCoRoutine::promise_type> coopter_t;

typedef struct {
  coopter_t coopter;
  struct kvm_regs orig_regs;
  void* cpu;
  long unsigned int retval;
  unsigned int counter;
} asid_details;

// Gross set of build_syscall functions without vaargs
void _build_syscall(syscall* s, unsigned int callno, int nargs,
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

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3, int unsigned long arg4,
    int unsigned long arg5) {
  _build_syscall(s, callno, 5, arg0, arg1, arg2, arg3, arg4, arg5);
}

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3, int unsigned long arg4) {
  _build_syscall(s, callno, 5, arg0, arg1, arg2, arg3, arg4, 0);
}

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2, int unsigned long arg3) {
  _build_syscall(s, callno, 4, arg0, arg1, arg2, arg3, 0, 0);
}

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1, int unsigned long arg2) {
  _build_syscall(s, callno, 3, arg0, arg1, arg2, 0, 0, 0);
}

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0,
    int unsigned long arg1) {
  _build_syscall(s, callno, 2, arg0, arg1, 0, 0, 0, 0);
}

void build_syscall(syscall* s, unsigned int callno, int unsigned long arg0) {
  _build_syscall(s, callno, 1, arg0, 0, 0, 0, 0, 0);
}

void build_syscall(syscall* s, unsigned int callno) {
  _build_syscall(s, callno, 0, /*args:*/0, 0, 0, 0, 0, 0);
}

__u64 memread(asid_details* r, __u64 gva, syscall* sc) {
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
      printf("[HYDE]: Fatal error, could not translate %llx and not able to inject a syscall\n", gva);
      assert(0);
    }
  }

  // Successfully translated GVA to GPA, now translate to HVA
  __u64 phys_addr;
  assert(kvm_host_addr_from_physical_physical_memory(trans.physical_address, &phys_addr) == 1);
  return phys_addr;
}


#endif
