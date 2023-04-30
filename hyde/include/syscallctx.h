#pragma once
#include <memory>
#include "hsyscall.h"
#include "syscall_coroutine.h"
#include <mutex>
#include <assert.h>

enum class RegIndex;

class SyscallCtx_impl;

// This is the interface plugins have to SyscallCtx objects
// They'll need to yield_syscall(ctx, ...) and should be able to get original syscall number/args
// as well as modifying the original syscall and setting a retval

class SyscallCtx {
public:
    SyscallCtx(void* cpu);

    /* Get originally requested syscall */
    hsyscall* get_orig_syscall() const;

    /* Get the originally requested syscall */
    hsyscall pending_sc() const;

    //uint64_t get_arg(RegIndex i) const; /* Get arg from orig */
    //void set_arg(RegIndex i, uint64_t val) const; /* Set arg in orig */

    uint64_t get_arg(int i) const; /* Get arg from orig_syscall */
    void set_arg(int i, uint64_t val) const; /* Set arg in orig_syscall */

    uint64_t get_result() const; /* Get result from last syscall */

    void set_nop(uint64_t retval) const; /* Replace orig_syscall with a no-op that returns retval */

    bool translate_gva(uint64_t gva, uint64_t* gpa);
    bool gpa_to_hva(uint64_t gpa, uint64_t *hva);

    // Before yielding a noreturn syscall, specify an exit value
    void set_noreturn(ExitStatus r);

    struct kvm_regs get_orig_regs() const; /* Get original regs*/

    /* set stack gva and size */
    void set_stack(uint64_t addr, size_t size);

    /* Return stack gva, stack_size */
    std::pair<uint64_t, size_t> get_stack(void);

    // Called by the runtime to clear the guest stack
    // This shoudl be called, then an munmap syscall run
    void clear_stack(void);

    /* Can the stack fit the provided size? False if
    * stack is unallocated or smaller than provided. */
    bool stack_can_fit(size_t requested_size);

    /* Does this context have a set stack? */
    bool has_stack(void);


private:
    friend class Runtime; // Give access to Runtime for constructing and managing SyscallCtx objects


    SyscallCtx();
    ~SyscallCtx();

    std::mutex stack_mtx_;
    uint64_t stack_;
    size_t stack_size_; // 0 if no stack

    // Unique pointer to the implementation
    std::unique_ptr<SyscallCtx_impl> pImpl;
};