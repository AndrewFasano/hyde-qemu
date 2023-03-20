#ifndef HYDE_MACRO_H
#define HYDE_MACRO_H

#include <tuple>
#include "hyde_common.h"

#ifdef WINDOWS
#define SKIP_SYSNO 0x01c0 // NtTestAlert - Probably need a better one
#else
#define SKIP_SYSNO __NR_getpid
#endif
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

#define set_CALLNO(s, x) (s).rax =x
#define set_ARG0(s, x)   (s).rdi =x
#define set_ARG1(s, x)   (s).rsi =x
#define set_ARG2(s, x)   (s).rdx =x
#define set_ARG3(s, x)   (s).r10 =x
#define set_ARG4(s, x)   (s).r8  =x
#define set_ARG5(s, x)   (s).r9  =x
#define set_RET(s, x)    (s).rax  =x

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
        printf("fatal: cannot read %lx\n", (long unsigned int)ptr); fflush(null); \
        assert(0 && "memory read failed"); \
      } \
    } \
  } while (0)

#define map_guest_pointer_status(details, varname, ptr, success) __memread_status(varname, details, ptr, success)
#define map_guest_pointer(details, varname, ptr) __memread(varname, details, ptr) 
#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return -1;};


/* Yield_from runs a coroutine, yielding the syscalls it yields, then finally returns a value that's co_returned from there */
#define yield_from(f, ...) \
  ({ \
    auto h = f(__VA_ARGS__).h_; \
    auto &promise = h.promise(); \
    uint64_t rv = 0; \
    while (!h.done()) { \
        co_yield promise.value_; \
        h(); /* Advance the other coroutine  */ \
        rv = promise.retval; \
    } \
    h.destroy(); \
    rv; \
  })

#endif