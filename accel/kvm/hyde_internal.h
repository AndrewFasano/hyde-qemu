#ifndef HYDE_HELPERS_H
#define HYDE_HELPERS_H

#ifdef __cplusplus
// C classes can include this file to get on_syscall + on_sysret. That's it

#include <linux/types.h>
#include <map>
#include <set>
#include <string>
#include "hyde_common.h"

#define R14_INJECTED 0xdeadbeef

// The following variables and functions are used in kvm/hyde.cpp but not
// called by external code.

std::map<std::string, coopter_f*> coopters; // filename -> should_coopt function
std::set<int> introspection_cpus; // CPUs that have syscall introspection enabled

std::set<long unsigned int> did_seccomp; // Procs that did a seccomp
std::set<syscall_context*> coopted_procs = {}; // Procs that have been coopted
std::set<std::string> pending_exits = {}; // Hyde progs that have requested to exit

// Procs that we expect to return twice - store once in _parents and once in _children
// Pop when we no longer expect
std::set<syscall_context*> double_return_parents = {};
std::set<syscall_context*> double_return_children = {};

#define IS_NORETURN_SC(x)(x == __NR_execve || \
                          x == __NR_execveat || \
                          x == __NR_exit || \
                          x == __NR_exit_group || \
                          x == __NR_rt_sigreturn)

#define PRINT_REG(REG) std::cout << "  " << #REG << ": " << std::hex << std::setw(16) << std::setfill('0') << regs.REG << std::endl;

// This param is from our custom kernel in uapi/linux/kvm.h
// #define KVM_HYDE_TOGGLE      _IOR(KVMIO,   0xbb, bool)
// this evalutes to 8001aebb
#define KVM_HYDE_TOGGLE 0x8001aebb

#ifdef WINDOWS
#define SKIP_SYSNO 0x01c0 // NtTestAlert - Probably need a better one
#else
#define SKIP_SYSNO __NR_getpid
#endif

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
  bool kvm_unload_hyde(void *cpu, int idx); // Unload all hyde programs
  bool kvm_load_hyde_capability(const char* path, void *cpu, int idx);
  bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx);
}

int getregs(syscall_context*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(syscall_context*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);

//bool translate_gva(syscall_context *r, uint64_t gva, uint64_t* hva); // Used in common
bool can_translate_gva(void*cpu, uint64_t gva);
void set_regs_to_syscall(syscall_context* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig);
bool is_syscall_targetable(int callno, unsigned long asid);

// Main logic - create coopter and advance on syscall/sysret
syscall_context* find_and_init_coopter(void* cpu, int callno, unsigned long asid, unsigned long pc);
extern "C" { // Called by KVM on syscall/sysret
#endif
  void on_syscall(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int callno,
                  long unsigned int asid, long unsigned int pc,
                  long unsigned int orig_rcx, long unsigned int orig_r11, long unsigned int r14, long unsigned int r15);

  void on_sysret(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int retval,
                  long unsigned int asid, long unsigned int pc, long unsigned int r14,
                  long unsigned int r15);
#ifdef __cplusplus
}
#endif

#endif
