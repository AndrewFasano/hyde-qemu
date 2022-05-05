#ifndef HYDE_H
#define HYDE_H

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);
extern "C" int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);

//RDI, RDX, R10, R8, R9
#define CALLNO(s) s.rax
#define ARG0(s) s.rdi
#define ARG1(s) s.rdx
#define ARG2(s) s.r10
#define ARG3(s) s.r8
#define ARG4(s) s.r9

#define set_CALLNO(s, x) s.rax =x
#define set_ARG0(s, x) s.rdi =x
#define set_ARG1(s, x) s.rdx =x
#define set_ARG2(s, x) s.r10 =x
#define set_ARG3(s, x) s.r8  =x
#define set_ARG4(s, x) s.r9  =x

#include <coroutine>
#include <exception>
#include <iostream>
 
// Co-routine classes based off https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
struct SyscCoRoutine {
  struct promise_type {
    unsigned value_;

    ~promise_type() { }

    SyscCoRoutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}
    std::suspend_always yield_value(unsigned value) {
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
  long unsigned int retval;
  long unsigned int last_inject;
  unsigned int counter;
  // more??
} asid_details;



#endif
