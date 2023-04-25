#include "hyde/src/syscallctx_internal.h"
#include "syscall_coroutine.h"
#include "qemu_api.h"
#include <linux/kvm.h>
#include <cassert>
#include <sys/syscall.h>

// Set on syscall, looked for on sysret
#define MAGIC_VALUE 0xdeadbeef

// Set on sysret, looked for on syscall - only when repeating
#define MAGIC_VALUE_REPEAT 0xb1ade001
/*
        syscall->ret              sysret->syscall
magic1 = 0xdeadbeef             | 0xb1ade000              KVM:R14
magic2 = key^sysret_pc          | key^syscall_pc          KVM:R15
magic3 = key                    | key                     KVM:R12
magic4 = sysret_pc              | syscall_pc              KVM:R13
*/

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


SyscallCtx_impl::SyscallCtx_impl(void* cpu, SyscallCtx* ctx) :
  magic_(0x12345678),
  ctr_(0),
  SyscallCtx_(ctx),
  coopter_(nullptr),
  has_custom_retval_(false),
  has_custom_return_(false),
  cpu_(cpu)
{
  // At initialization, we read original registers
  assert(cpu != nullptr);

  if (!get_regs(cpu, &orig_regs_)) {
    printf("Failed to get orig registers with cpu at %p\n", cpu);
    assert(0);
  }

  // We want orig_regs to store our pre-syscall registers. But when we capture this info, we've already run
  // our em_syscall function in kvm and we've set r11 = rflags, rcx = pc+2, pc=lstar.
  // In our orig_regs, we want to store the original values. Does it matter? Don't think so?

  // PC is now in RCX
  //orig_regs_.rip = orig_regs_.rcx; // Next instruction after syscall (maybe not +2?)

  // Rflags in r11
  orig_regs_.rflags = (orig_regs_.r11 & 0x3c7fd7) & 0x2;

  // And rcx, r11 are clobbered for good. Be explicit about it
  //orig_regs_.rcx = 0x41424344;
  //orig_regs_.r11 = 0x61626364;

  // And let's also hold nto the original 

  // Parse registers to get orig syscall info
  // Yep it's duplicative!
  orig_syscall_ = new hsyscall(__get_arg(orig_regs_, RegIndex::CALLNO));
  uint64_t args[6];
  for (int i = 0; i < 6; i++) {
    args[i] = get_arg((RegIndex)i);
  }
  orig_syscall_->set_args(6, args);
}

SyscallCtx_impl::~SyscallCtx_impl() {
  delete orig_syscall_;
  if (coopter_ != nullptr) coopter_.destroy();
}

uint64_t SyscallCtx_impl::get_arg(RegIndex i) const {
  return __get_arg(orig_regs_, i);
}

bool SyscallCtx_impl::inject_syscall(void* cpu, hsyscall sc) {
  cpu_ = cpu;
  kvm_regs r = orig_regs_;

  // How do current registers compare to original?

// ORIG rcx, R11 are junk. Orig RCX is in RIP
// ORIG rip is r2.rcx

  //kvm_regs r2;
  //assert(get_regs(cpu, &r2));
  //pretty_print_diff_regs(r, r2);

  // TODO: we should support stack-based args too, but might need to inject to page in stack
  __set_arg(r, RegIndex::CALLNO, sc.callno);
  for (size_t i = 0; i < sc.nargs; i++) {
    uint64_t value = sc.args[i].is_ptr ? sc.args[i].guest_ptr : sc.args[i].value;
    __set_arg(r, (RegIndex)i, value);
  }

  // XXX: Can we safely inject into either of these - should be possible
  // with some specially-crafted custom return addresses/state for children
  assert(!IS_CLONE_SC(sc.callno) && !IS_FORK_SC(sc.callno));

  // If this syscall will return, we inject into R12-R15 and cleanup on return
  // Otherwise we just inject this syscall and can't get the results
  bool set_magic = !IS_NORETURN_SC(sc.callno);
  if (set_magic) {
    r.r12 = reinterpret_cast<uint64_t>(SyscallCtx_);
    //r.r13 = r.rip; // XXX on construct we moved rcx into our rip since that's what it is
    r.r13 = r.rcx;
    r.r14 = MAGIC_VALUE;
    r.r15 = r.r12 ^ r.r13;
  }

  assert(set_regs(cpu, &r));
  return set_magic;
}

  void SyscallCtx_impl::restore_magic_regs(void* cpu, kvm_regs &new_regs) {
    // Restore R12, R13, R14, R15 from orig_regs - this is 
    // when we hit a syscall that we've set up from a sysret
    cpu_ = cpu;
    new_regs.r12 = orig_regs_.r12;
    new_regs.r13 = orig_regs_.r13;
    new_regs.r14 = orig_regs_.r14;
    new_regs.r15 = orig_regs_.r15;
  }


void SyscallCtx_impl::at_sysret_redo_syscall(void* cpu, uint64_t sc_pc, kvm_regs& new_regs) {
  // In a sysert we want to go back to the syscall insn at sc_pc.
  //fprintf(fp, "In sysret, we want to want to re-execute syscall insn at %lx, object is at %p\n", sc_pc, this);

  cpu_ = cpu;
  new_regs.r12 = reinterpret_cast<uint64_t>(SyscallCtx_);
  new_regs.r13 = sc_pc;
  new_regs.r14 = MAGIC_VALUE_REPEAT;
  new_regs.r15 = new_regs.r12 ^ new_regs.r13;

  // And change our PC to sc_pc as well via RCX. This works, we used it previously:
  // https://github.com/AndrewFasano/hhyde-qemu/blob/6b15778ff2e2f56e3b3311f2a4a3b608026e4ba5/accel/kvm/hyde.cpp#L539
  new_regs.rip = sc_pc;

  assert(set_regs(cpu, &new_regs));
}

bool SyscallCtx_impl::translate_gva(uint64_t gva, uint64_t* gpa) {
    return ::translate_gva(cpu_, gva, gpa);
}
bool SyscallCtx_impl::gpa_to_hva(uint64_t gpa, uint64_t *hva) {
    return ::gpa_to_hva(cpu_, gpa, hva);
}
