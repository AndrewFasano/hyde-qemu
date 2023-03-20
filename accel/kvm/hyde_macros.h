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
#define set_ARG0(s, x)   (s).rdi = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_ARG1(s, x)   (s).rsi = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_ARG2(s, x)   (s).rdx = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_ARG3(s, x)   (s).r10 = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_ARG4(s, x)   (s).r8  = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_ARG5(s, x)   (s).r9  = ((x.is_ptr) ? x.guest_ptr : x.value )
#define set_RET(s, x)    (s).rax = ((x.is_ptr) ? x.guest_ptr : x.value )

// macros for memory read and syscall yielding
#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)
#define __scratchvar(x) TOKENPASTE2(x, __LINE__ )


#endif