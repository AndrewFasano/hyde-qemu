#ifndef HYDE_H
#define HYDE_H


#include <exception>
#include <linux/kvm.h>
#include <cassert>

#include "hyde_common.h" // Sets debug+windows, typedefs hsyscall
#include "hyde_macros.h"
#include "hyde_coro.h"

typedef struct _asid_details {
  coopter_t coopter;
  struct kvm_regs orig_regs;
  hsyscall *orig_syscall;
  void* cpu;
  long unsigned int last_sc_retval;
#ifdef DEBUG
  unsigned int injected_callno; // Debug only
#endif
  uint64_t asid;
  uint64_t orig_rcx;
  uint64_t orig_r11;
  bool use_orig_regs; // If set, after sysret we'll restore RCX/R11 to their pre-syscall values
  unsigned long custom_return;
  bool modify_original_args;
  std::function<void(struct kvm_regs*)> *modify_on_ret;

  std::function<void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)> *on_ret;
  hsyscall scratch; // TODO: get rid of this, only used in outdated code
} asid_details;


void dump_syscall(hsyscall h);

int getregs(asid_details*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(asid_details*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);

#if 0
void build_syscall(hsyscall*, unsigned int callno);
void build_syscall(hsyscall*, unsigned int, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
#else
void _build_syscall(hsyscall*, unsigned int callno, int nargs, ...);
#endif

// Debug helper function
void dump_sc(struct kvm_regs r);
void dump_sc_with_stack(asid_details* a, struct kvm_regs r);
void dump_regs(struct kvm_regs r);

// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

bool translate_gva(asid_details *r, ga* gva, uint64_t* hva);
// Coroutine helpers - HyDE programs can yield_from these and the helpers can inject
// more syscalls if they'd like
SyscCoro ga_memcpy_one(asid_details* r, void* out, ga* gva, size_t size);
SyscCoro ga_memcpy(asid_details* r, void* out, ga* gva, size_t size);
SyscCoro ga_memread(asid_details* r, void* out, ga* gva, size_t size);
SyscCoro ga_memwrite(asid_details* r, ga* gva, void* in, size_t size);
//SyscCoro ga_memmove(asid_details* r, ga* dest, void* src, size_t size);
SyscCoro ga_map(asid_details* r,  ga* gva, void** host, size_t min_size);

// Type signature for a function *hyde programs* must implement. Implemenations should
// returns a pointer to a local (extern C) coroutine function if the syscall should be
// co-opted, otherwise NULL
extern "C" {
  create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);
}

// XXX WIP
asid_details* hack;
template <long SyscallNumber, typename Function, typename... Args>
hsyscall* inject_syscall(Function syscall_func, Args... args);
//#define yield_syscall(details, func, ...) 0; // XXX
//#define yield_syscall2(details, func, ...) hack=details, inject_syscall<SYS_##func>(::func, ##__VA_ARGS__)

#endif