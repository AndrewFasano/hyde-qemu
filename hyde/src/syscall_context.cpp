#include "syscall_context.h"
#include "hyde/src/syscall_context_internal.h"

// Nobody can initialize this class, it's only created via the pImpl
//syscall_context::syscall_context()
//    : pImpl(std::make_unique<syscall_context_impl>(nullptr)) {
//}

syscall_context::syscall_context(void* cpu, uint64_t orig_rcx, uint64_t orig_r11) : pImpl(std::make_unique<syscall_context_impl>(cpu, this, orig_rcx, orig_r11)) {}

syscall_context::syscall_context(const syscall_context& other, void* cpu) {
      pImpl = std::make_unique<syscall_context_impl>(*other.pImpl, cpu, this);
}


//syscall_context::syscall_context() : pImpl(std::make_unique<syscall_context_impl>(*this)) {}


syscall_context::~syscall_context() = default;

uint64_t syscall_context::get_arg(RegIndex i) const {
  return pImpl->get_arg(i);
}

void syscall_context::set_child_coopter(create_coopter_t f) const {
  return pImpl->set_child_coopter(f);
}

uint64_t syscall_context::get_result() const {
  return pImpl->get_last_rv();
}

hsyscall* syscall_context::get_orig_syscall() const {
  return pImpl->get_orig_syscall();
}

bool syscall_context::translate_gva(uint64_t gva, uint64_t* gpa) {
    return pImpl->translate_gva(gva, gpa);
}
bool syscall_context::gpa_to_hva(uint64_t gpa, uint64_t* hva) {
    return pImpl->gpa_to_hva(gpa, hva);
}

// Implement other public interface methods
