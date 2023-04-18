#include "syscall_context.h"
#include "hyde/src/syscall_context_internal.h"

// Nobody can initialize this class, it's only created via the pImpl
//syscall_context::syscall_context()
//    : pImpl(std::make_unique<syscall_context_impl>(nullptr)) {
//}

// cpu arg (i.e., something created by runtime)
syscall_context::syscall_context(void* cpu) : pImpl(std::make_unique<syscall_context_impl>(cpu, this)) {}

// No arg, no cpu (i.e., something created by a plugin)
syscall_context::syscall_context() : pImpl(std::make_unique<syscall_context_impl>(nullptr, this)) {}

// Copy constructor
syscall_context::syscall_context(const syscall_context& other) {
      pImpl = std::make_unique<syscall_context_impl>(*other.pImpl);
}

//syscall_context::syscall_context() : pImpl(std::make_unique<syscall_context_impl>(*this)) {}


syscall_context::~syscall_context() = default;

uint64_t syscall_context::get_arg(RegIndex i) const {
  return pImpl->get_arg(i);
}

uint64_t syscall_context::get_result() const {
  return pImpl->get_last_rv();
}

hsyscall* syscall_context::get_orig_syscall() const {
  return pImpl->get_orig_syscall();
}

// Implement other public interface methods
