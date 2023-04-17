#include "hyde/src/syscall_context_internal.h"

syscall_context_impl::syscall_context_impl(int syscall_number)
    : syscall_number_(syscall_number) {
}

syscall_context_impl::~syscall_context_impl() = default;

int syscall_context_impl::get_syscall_number() const {
  return syscall_number_;
}

struct kvm_regs syscall_context_impl::get_orig_regs() const {
  return orig_regs_;
}

// Implement other internal methods
