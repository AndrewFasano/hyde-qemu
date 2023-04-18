#pragma once
#include <memory>
#include "hsyscall.h"

enum class RegIndex;

class syscall_context_impl;

// This is the interface plugins have to syscall_context objects
// They'll need to yield_syscall(ctx, ...) and should be able to get original syscall number/args
// as well as modifying the original syscall and setting a retval

class syscall_context {
public:
    syscall_context(void* cpu);
    //syscall_context(const syscall_context&) = delete;
    syscall_context(const syscall_context& other);
    //syscall_context& operator=(const syscall_context&) = delete;

    hsyscall* get_orig_syscall() const;
    uint64_t get_arg(RegIndex i) const;

    uint64_t get_result() const;

    bool translate_gva(uint64_t gva, uint64_t* gpa);
    bool gpa_to_hva(uint64_t gpa, uint64_t *hva);

    struct kvm_regs get_orig_regs() const;
    // Other public methods for plugins to access syscall_context information

private:
    friend class Runtime; // Give access to Runtime for constructing and managing syscall_context objects


    syscall_context();
    ~syscall_context();

    // Unique pointer to the implementation
    std::unique_ptr<syscall_context_impl> pImpl;
};

#if 0

/* This structure stores details about a given process that we are co-opting.
 * It contains a pointer to the coroutine that is simulating the process's execution.
 * It also contains a pointer to the original system call that the process was executing.
 * Finally, it contains a pointer to the original registers that the process was executing.
*/
struct syscall_context {

  //std::function<void(_syscall_context*, void*, unsigned long, unsigned long, unsigned long)> *on_ret; // Unused

  syscall_context(void *cpu, uint64_t asid) :
    coopter(nullptr),
    name(""),
    cpu(cpu),
    last_sc_retval(0),
    child(false),
    asid(asid),
    orig_rcx(0),
    orig_r11(0),
    use_orig_regs(false),
    custom_return(0) {

        assert(kvm_vcpu_ioctl(cpu, KVM_GET_REGS, &orig_regs) == 0);
        orig_syscall = new hsyscall(get_arg(RegIndex::CALLNO));
        uint64_t args[6];
        for (int i = 0; i < 6; i++) {
            args[i] = details.get_arg((RegIndex)i);
        }
        orig_syscall->set_args(6, args);
    };

  //void setCoopter(coopter_t c) { coopter = c; }
  //coopter_t getCoopter() const { return coopter; }
};
#endif