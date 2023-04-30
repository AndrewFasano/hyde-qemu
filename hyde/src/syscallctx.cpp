#include "syscallctx.h"
#include "hyde/src/syscallctx_internal.h"

// Nobody can initialize this class, it's only created via the pImpl

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
    if (pImpl->has_custom_retval() || pImpl->has_custom_return()) [[unlikely]] {
      printf("USER ERROR: You can't set a custom retval or ret addr in a noreturn syscall\n");
      assert(0);
    }
    pImpl->set_noreturn(r);
}

// The stack functions all use a mutex, not because we think
// we could possibly need it, but becasue if we ever managed
// to have two coroutines with the same context we'd want to fail fast

void SyscallCtx::set_stack(uint64_t addr, uint64_t size) {
    std::lock_guard<std::mutex> lock(stack_mtx_);
    //printf("Set stack for %p to %lx size %ld\n", this, addr, size);
    assert(stack_size_ == 0 && "Stack already set");
    stack_size_ = size;
    stack_ = addr;
}

std::pair<uint64_t, size_t> SyscallCtx::get_stack(void) {
    std::lock_guard<std::mutex> lock(stack_mtx_);
    assert(stack_size_ != 0 && "Stack not set");
    //printf("Get stack for %p: %lx size %ld\n", this, stack_, stack_size_);
    return std::make_pair(stack_, stack_size_);
}

// Called by the runtime to clear the guest stack
// This shoudl be called, then an munmap syscall run
void SyscallCtx::clear_stack(void) {
    std::lock_guard<std::mutex> lock(stack_mtx_);
    assert(stack_size_ != 0 && "Stack not set");
    //printf("Clear stack for %p. Had %lx, size %ld\n", this, stack_, stack_size_);
    stack_size_ = 0;
    stack_ = 0;
}

/* Can the stack fit the provided size? False if
  * stack is unallocated or smaller than provided. */
bool SyscallCtx::stack_can_fit(size_t requested_size) {
    std::lock_guard<std::mutex> lock(stack_mtx_);
    //printf("Can stack stack for %p which is sz %ld fit %ld?", this, stack_size_, requested_size);
    return stack_size_ >= requested_size;
}

bool SyscallCtx::has_stack(void) {
    std::lock_guard<std::mutex> lock(stack_mtx_);
    return stack_size_ != 0;
}