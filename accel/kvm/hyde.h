#ifndef HYDE_H
#define HYDE_H

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);

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

#endif
