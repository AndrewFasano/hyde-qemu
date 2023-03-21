#ifndef HYDE_HELPERS_H
#define HYDE_HELPERS_H

#include <linux/types.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include "hyde_common.h"

// The following variables and functions are used in kvm/hyde.cpp but not
// called by external code.

std::map<std::string, coopter_f*> coopters; // function which returns coroutine or NULL
std::map<std::pair<long unsigned int, long unsigned int>, asid_details*> active_details; // (asid,cpuid)->details
std::set<long unsigned int> did_seccomp;

// This param is from our custom kernel in uapi/linux/kvm.h
// #define KVM_HYDE_TOGGLE      _IOR(KVMIO,   0xbb, bool)
// this evalutes to 8001aebb
#define KVM_HYDE_TOGGLE 0x8001aebb

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


// Can we include sysemu/kvm.h to get these?
extern "C" {
  int kvm_vcpu_ioctl(void *cpu, int type, ...);
  int kvm_vcpu_ioctl_pause_vm(void *cpu, int type, ...);
  int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);
  unsigned long get_cpu_id(void *cpu);
}

void enable_syscall_introspection(void* cpu, int idx);
void disable_syscall_introspection(void* cpu);
bool try_load_coopter(std::string path, void* cpu, int idx);
bool try_unload_coopter(std::string path, void* cpu, int idx);

extern "C" { // Called by the qemu monitor
  bool kvm_load_hyde_capability(const char* path, void *cpu, int idx);
  bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx);
}

int getregs(asid_details*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(asid_details*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);

//bool translate_gva(asid_details *r, uint64_t gva, uint64_t* hva); // Used in common
bool can_translate_gva(void*cpu, uint64_t gva);
void set_regs_to_syscall(asid_details* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig);
bool is_syscall_targetable(int callno, unsigned long asid);

// Main logic - create coopter and advance on syscall/sysret
asid_details* find_and_init_coopter(void* cpu, int callno, unsigned long asid, unsigned long pc);
extern "C" { // Called by KVM on syscall/sysret
  void on_syscall(void *cpu, long unsigned int callno, long unsigned int asid, long unsigned int pc, long unsigned int orig_rcx, long unsigned int orig_r11);
  void on_sysret(void *cpu, long unsigned int retval, long unsigned int asid, long unsigned int pc);
} 

#endif
