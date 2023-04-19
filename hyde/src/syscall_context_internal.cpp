#include "hyde/src/syscall_context_internal.h"
#include "syscall_coroutine.h"
#include "qemu_api.h"
#include <linux/kvm.h>
#include <cassert>

#define REG_ACCESS(reg, idx) \
    ((idx == RegIndex::CALLNO || idx == RegIndex::RET) ? (reg).rax : \
     (idx == RegIndex::ARG0) ? (reg).rdi : \
     (idx == RegIndex::ARG1) ? (reg).rsi : \
     (idx == RegIndex::ARG2) ? (reg).rdx : \
     (idx == RegIndex::ARG3) ? (reg).r10 : \
     (idx == RegIndex::ARG4) ? (reg).r8 : \
     (idx == RegIndex::ARG5) ? (reg).r9 : \
     throw std::runtime_error("Invalid register index"))

// Define a macro for getting a specific register value from kvm_regs
#define __get_arg(regs, idx) REG_ACCESS(regs, idx)

// Define a macro for setting a specific register value in kvm_regs
#define __set_arg(regs, idx, val) REG_ACCESS(regs, idx) = (val)

#define IS_NORETURN_SC(x)(x == __NR_execve || \
                          x == __NR_execveat || \
                          x == __NR_exit || \
                          x == __NR_exit_group || \
                          x == __NR_rt_sigreturn)

syscall_context_impl::syscall_context_impl(void* cpu, syscall_context* ctx) :
  //last_sc_retval(0),
  syscall_context_(ctx),
  coopter_(nullptr),
  has_custom_retval_(false),
  has_custom_return_(false),
  cpu_(cpu)
{
  // At initialization, we read original registers
  assert(cpu != nullptr);

  if (!set_orig_regs(cpu)) {
    printf("Failed to get orig registers with cpu at %p\n", cpu);
    assert(0);
  }

  // Parse registers to get orig syscall info
  // Yep it's duplicative!
  orig_syscall_ = new hsyscall(__get_arg(orig_regs_, RegIndex::CALLNO));
  uint64_t args[6];
  for (int i = 0; i < 6; i++) {
    args[i] = get_arg((RegIndex)i);
  }
  orig_syscall_->set_args(6, args);
}

// Copy an existing syscall_ctx into a new one - e.g., after a fork
syscall_context_impl::syscall_context_impl(const syscall_context_impl& other, void* cpu, syscall_context* ctx) :
  syscall_context_(ctx),
  orig_syscall_(new hsyscall(*other.orig_syscall_)),
  coopter_(nullptr),
  has_custom_retval_(other.has_custom_retval_),
  custom_retval_(other.custom_retval_),
  has_custom_return_(other.has_custom_return_),
  custom_return_(other.custom_return_),
  cpu_(cpu)
{
  // XXX can't duplicate coopter: instead we launch child coopter
  assert(child_coopter_ != nullptr);
  coopter_ = (child_coopter_)(syscall_context_).h_;
  child_coopter_ = nullptr;
}

void syscall_context_impl::set_child_coopter(create_coopter_t f) {
  child_coopter_ = f;
}


syscall_context_impl::~syscall_context_impl() {
  delete orig_syscall_;
  if (coopter_ != nullptr) coopter_.destroy();
}

uint64_t syscall_context_impl::get_arg(RegIndex i) const {
  return __get_arg(orig_regs_, i);
}

bool syscall_context_impl::set_syscall(void* cpu, hsyscall sc) {
  kvm_regs r = orig_regs_;
  __set_arg(r, RegIndex::CALLNO, sc.callno);

  // TODO: we should support stack-based args too
  for (size_t i = 0; i < sc.nargs; i++) {
    uint64_t value = sc.args[i].is_ptr ? sc.args[i].guest_ptr : sc.args[i].value;
    __set_arg(r, (RegIndex)i, value);
  }

  // Set our magic values, unless it won't return (then we can't detect on return,
  // and we can't mess things up by changing state)
  if (!IS_NORETURN_SC(sc.callno)) [[likely]] {
    r.r14 = R14_INJECTED;
    r.r15 = (uint64_t)syscall_context_;
  }

  assert(set_regs(cpu, &r));

  // return false if it's noreturn
  return !IS_NORETURN_SC(sc.callno);
}

bool syscall_context_impl::set_orig_regs(void* cpu) {
    // Use an IOCTL to read the registers from the guest CPU
    // and store in this context
    return get_regs(cpu, &orig_regs_);
}

bool syscall_context_impl::translate_gva(uint64_t gva, uint64_t* gpa) {
    return ::translate_gva(cpu_, gva, gpa);
}
bool syscall_context_impl::gpa_to_hva(uint64_t gpa, uint64_t *hva) {
    return ::gpa_to_hva(cpu_, gpa, hva);
}
