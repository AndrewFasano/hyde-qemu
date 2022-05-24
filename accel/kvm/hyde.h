#ifndef HYDE_H
#define HYDE_H

#include <coroutine>
#include <exception>
#include <linux/kvm.h>
#include <cassert>

//#define DEBUG
#define WINDOWS

//rax callno, args in RDI, RSX, RDX, R10, R8, R9
#define CALLNO(s) (s).rax
#define ARG0(s) (s).rdi
#define ARG1(s) (s).rsi
#define ARG2(s) (s).rdx
#define ARG3(s) (s).r10
#define ARG4(s) (s).r8
#define ARG5(s) (s).r9

#define get_arg(s, i)  ((i == 0) ? ARG0(s) : \
                        (i == 1) ? ARG1(s) : \
                        (i == 2) ? ARG2(s) : \
                        (i == 3) ? ARG3(s) : \
                        (i == 4) ? ARG4(s) : \
                        (i == 5) ? ARG5(s) : \
                         -1)

#define set_CALLNO(s, x) s.rax =x
#define set_ARG0(s, x) s.rdi =x
#define set_ARG1(s, x) s.rsi =x
#define set_ARG2(s, x) s.rdx =x
#define set_ARG3(s, x) s.r10 =x
#define set_ARG4(s, x) s.r8  =x
#define set_ARG5(s, x) s.r9  =x
#define set_RET(s, x) s.rax  =x

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
#ifdef DEBUG
  unsigned int injected_callno; // Debug only
#endif
  unsigned int asid;
  bool skip;
  //bool finished;
  unsigned long custom_return;
  bool modify_original_args;
  hsyscall scratch;
} asid_details;

__u64 memread(asid_details*, __u64, hsyscall*);
__u64 translate(void *cpu, __u64 gva, int* status);
int getregs(asid_details*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(asid_details*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);
void build_syscall(hsyscall*, unsigned int callno);
void build_syscall(hsyscall*, unsigned int, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);

// macros for memory read and syscall yielding
#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)
#define __scratchvar(x) TOKENPASTE2(x, __LINE__ )

#ifdef DEBUG
#define __memread_status(out, r, ptr, success) do { \
    *success = false; \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      printf("Failed to read %lx - inject a syscall\n", (unsigned long)ptr); \
      co_yield __scratchvar(sc); \
      printf("SC returns 0x%lx\n", r->retval); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out != (__u64)-1) { \
        *success = true;\
      } \
    } else { *success = true; } \
  } while (0)
#else
#define __memread_status(out, r, ptr, success) do { \
    *success = false; \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      co_yield __scratchvar(sc); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out != (__u64)-1) { \
        *success = true;\
      } \
    } else { *success = true; } \
  } while (0)

#endif

#define __memread(out, r, ptr) do { \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      co_yield __scratchvar(sc); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out == (__u64)-1) { \
        printf("FATAL: cannot read %lx\n", (long unsigned int)ptr); fflush(NULL); \
        assert(0 && "memory read failed"); \
      } \
    } \
  } while (0)

hsyscall* _allocate_hsyscall();

#define map_guest_pointer_status(details, varname, ptr, success) __memread_status(varname, details, ptr, success)
#define map_guest_pointer(details, varname, ptr) __memread(varname, details, ptr)

#define yield_syscall(r, ...) (build_syscall(&r->scratch, __VA_ARGS__), co_yield r->scratch, r->retval)
#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return;};

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
  //printf("\t RBP: %016llx    R8 %016llx    R9 %016llx    R10 %016llx    R11 %016llx    R12 %016llx    R13 %016llx\n", r.rbp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13);
  //printf("\t R14: %016llx    R15: %016llx    RFLAGS %016llx\n", r.r14, r.r15, r.rflags);
}

// create_coopt_t type takes in asid_details*, returns SysCoroutine
typedef SyscCoroutine(create_coopt_t)(asid_details*);
typedef create_coopt_t*(coopter_f)(void*, long unsigned_int);

// Function *a capability must provide* -  extern C to avoid mangling
// Returns a pointer to a local (extern C) coroutine function if the syscall should be co-opted, otherwise NULL
extern "C" {
  create_coopt_t* should_coopt(void*cpu, long unsigned int callno);
}

#endif
