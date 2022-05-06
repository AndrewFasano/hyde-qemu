#ifndef HYDE_H
#define HYDE_H

#include <coroutine>
#include <exception>
#include <linux/kvm.h>
#include <cassert>

//rax callno, args in RDI, RDX, RSI, R10, R8, R9
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

__u64 memread(asid_details*, __u64, hsyscall*);
int getregs(asid_details *, struct kvm_regs *);
void build_syscall(hsyscall*, unsigned int callno);
void build_syscall(hsyscall*, unsigned int, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);


#endif
