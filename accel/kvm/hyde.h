#ifndef HYDE_H
#define HYDE_H

#include <coroutine>
#include <exception>
#include <linux/kvm.h>

typedef struct {
  unsigned int callno;
  unsigned long args[6];
  unsigned int nargs;
} hsyscall;

// Co-routine classes based off https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
struct SyscCoroutine {
  struct promise_type {
    hsyscall value_;

    ~promise_type() { }

    SyscCoroutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}
    std::suspend_always yield_value(hsyscall value) {
      value_ = value;
      return {};
    }
    void return_void() {}

  };

  std::coroutine_handle<promise_type> h_;
};

typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;
 
typedef struct {
  coopter_t coopter;
  struct kvm_regs orig_regs;
  void* cpu;
  long unsigned int retval;
  unsigned int counter;
  bool skip;
} asid_details;


#endif
