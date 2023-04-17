#include "hyde/include/syscall_context.h"
#include "hyde/src/syscall_context_internal.h"

syscall_context::syscall_context()
    : pImpl(std::make_unique<syscall_context_impl>(0)) {
}

syscall_context::~syscall_context() = default;

int syscall_context::get_syscall_number() const {
  return pImpl->get_syscall_number();
}

struct kvm_regs syscall_context::get_orig_regs() const {
  return pImpl->get_orig_regs();
}

// Implement other public interface methods
