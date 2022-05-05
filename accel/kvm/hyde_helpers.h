#ifndef HYDE_HELPERS_H
#define HYDE_HELPERS_H

#include <linux/types.h>
#include <vector>
#include <map>
#include "hyde.h"

// Internal helper functions for HyDE

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);
extern "C" int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);

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

#define GETREGS(r, regs) assert(kvm_vcpu_ioctl(r->cpu, KVM_GET_REGS, &regs) == 0);

typedef std::pair<bool(*)(void*, long unsigned int), SyscCoroutine(*)(asid_details*)> coopter_pair;

__u64 memread(asid_details*, __u64, syscall*);

void build_syscall(syscall*, unsigned int callno);
void build_syscall(syscall*, unsigned int, int unsigned long);
void build_syscall(syscall*, unsigned int, int unsigned long, int unsigned long);
void build_syscall(syscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(syscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(syscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(syscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);

#endif
