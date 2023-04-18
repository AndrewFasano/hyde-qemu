#ifndef HYDE_H
#define HYDE_H

#include <sys/types.h>
#include <cstring>
#include <string>
#include <linux/kvm.h>
#include <coroutine>
#include <cstdint>
#include <stdexcept>
#include <cassert>
#include <functional>
#include <unordered_map>
#include "syscall_context.h"

// XXX OLD?

#error "You want plugin_common.h for now"

#if 0
// Seems to cause compile time errors only for clean builds
void dump_syscall(hsyscall *s) {
#ifdef HYDE_DEBUG
  printf("Syscall %lu (with %d args):", s->callno, s->nargs);
  for (int i=0; i<s->nargs; i++) {
    printf(" %lu", s->args[i].value);
  }
  puts("");
#endif
}
#endif

// Function to set the argument value by index given an hsyscall_arg
#if 0
inline void set_arg(struct kvm_regs& s, RegIndex idx, hsyscall_arg arg) {
    // XXX: callno and ret can't be pointers
    uint64_t value = arg.is_ptr ? arg.guest_ptr : arg.value;
    switch (idx) {
        case RegIndex::ARG0: s.rdi = value; break;
        case RegIndex::ARG1: s.rsi = value; break;
        case RegIndex::ARG2: s.rdx = value; break;
        case RegIndex::ARG3: s.r10 = value; break;
        case RegIndex::ARG4: s.r8 = value; break;
        case RegIndex::ARG5: s.r9 = value; break;
        default: throw std::runtime_error("Invalid register index");
    }
}

// CALLNO/RET are set as uint64_ts, not hsyscall_args
inline void set_arg(struct kvm_regs& s, RegIndex idx, uint64_t value) {
    switch (idx) {
        case RegIndex::CALLNO:
        case RegIndex::RET: s.rax = value; break;
        default: throw std::runtime_error("Invalid register index");
    }
}
#endif


// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscallCoroutine(syscall_context*)
//typedef SyscallCoroutine(create_coopt_t)(syscall_context*);
using create_coopt_t = SyscallCoroutine(*)(syscall_context*);


// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(syscall_context*)
using coopter_f = create_coopt_t*(*)(void*, long unsigned int, long unsigned int, unsigned int);

// Pointer to an *uninitialized* syscall coroutine function

//SyscallCoroutine (*all_syscalls)(syscall_context*);

//typedef SyscallCoroutine (*CoroutinePtr)(syscall_context*);
//using CoroutineFnPtr = SyscallCoroutine<void> (*)(int);

using SyscallCoroutinePtr = SyscallCoroutine(*)(syscall_context*);
using ScMap = std::unordered_map<int, SyscallCoroutinePtr>;
// Define the interface for a plugin's initialization function
using PluginInitFunc = void(*)(ScMap& syscall_map,  SyscallCoroutinePtr all);

bool translate_gva(syscall_context *r, uint64_t gva, uint64_t* hva); // Coroutine helpers use this for translation
uint64_t kvm_translate(void *cpu, uint64_t gva);
int kvm_host_addr_from_physical_memory_ext(uint64_t gpa, uint64_t *phys_addr);
int getregs(syscall_context *r, struct kvm_regs *regs);

// I've never seen this fail, but it feels safer than an assert?
#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return ExitStatus::SINGLE_FAILURE;};

// Type signature for a function *hyde programs* must implement. Implemenations should
// returns a pointer to a local (extern C) coroutine function if the syscall should be
// co-opted, otherwise NULL
//extern "C" {
//  create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);
//}

#endif