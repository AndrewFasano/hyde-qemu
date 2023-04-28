#include "syscallctx.h"
#include "hyde/src/syscallctx_internal.h"

// Nobody can initialize this class, it's only created via the pImpl
//SyscallCtx::SyscallCtx()
//    : pImpl(std::make_unique<SyscallCtx_impl>(nullptr)) {
//}

SyscallCtx::SyscallCtx(void* cpu)
: stack_(0), stack_size_(0),
  pImpl(std::make_unique<SyscallCtx_impl>(cpu, this)) {};

SyscallCtx::~SyscallCtx() = default;

// GET and SET args in the hsyscall object
uint64_t SyscallCtx::get_arg(int i) const {
  return pImpl->get_arg(i);
}

void SyscallCtx::set_arg(int i, uint64_t new_val) const {
  pImpl->set_arg(i, new_val);
}

uint64_t SyscallCtx::get_result() const {
  return pImpl->get_last_rv();
}

void SyscallCtx::set_nop(uint64_t result) const {
  pImpl->set_nop(result);
}

hsyscall* SyscallCtx::get_orig_syscall() const {
  return pImpl->get_orig_syscall();
}

hsyscall SyscallCtx::pending_sc() const {
  return *pImpl->get_orig_syscall();
}

bool SyscallCtx::translate_gva(uint64_t gva, uint64_t* gpa) {
    return pImpl->translate_gva(gva, gpa);
}
bool SyscallCtx::gpa_to_hva(uint64_t gpa, uint64_t* hva) {
    return pImpl->gpa_to_hva(gpa, hva);
}

void SyscallCtx::set_noreturn(ExitStatus r) {
    pImpl->set_noreturn(r);
}