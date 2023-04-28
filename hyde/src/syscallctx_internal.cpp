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
  cpu_(cpu),
  is_noreturn_(false)
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

  // Parse registers to get orig syscall info
  // Yep it's duplicative!
  orig_syscall_ = new hsyscall(__get_arg(orig_regs_, RegIndex::CALLNO));
  uint64_t args[6];
  for (int i = 0; i < 6; i++) {
    args[i] = get_arg_((RegIndex)i);
  }
  orig_syscall_->set_args(6, args);
}

SyscallCtx_impl::~SyscallCtx_impl() {
  if (SyscallCtx_->stack_ != 0) {
    std::cerr << "USER ERROR: At coroutine destruction, stack still exists in guest memory - missing call to finish()" << std::endl;
  }

  delete orig_syscall_;
  if (coopter_ != nullptr) coopter_.destroy();
}

uint64_t SyscallCtx_impl::get_arg(int i) const {
  return orig_syscall_->get_arg(i); // Integer
}

uint64_t SyscallCtx_impl::get_arg_(RegIndex i) const {
  return __get_arg(orig_regs_, i); // RegIndex
}

void SyscallCtx_impl::set_nop(uint64_t retval) {
  orig_syscall_->callno = SYS_getpid; // No side effects
  set_custom_retval(retval);
}

void SyscallCtx_impl::set_arg(int i, uint64_t val) const {
  return orig_syscall_->set_arg(i, val);
}

bool SyscallCtx_impl::inject_syscall(void* cpu, hsyscall sc) {
  cpu_ = cpu;
  kvm_regs r = orig_regs_;

  if (is_noreturn_) {
    //std::cout << "Injecting a noreturn syscall: " << sc.callno << std::endl;
    kvm_regs r2;
    assert(get_regs(cpu, &r2));

    // Seems like we *don't* want this
    //r.rflags = r2.rflags; // Keep changes to RFLAGS?
  }


  // TODO: we should support stack-based args too, but might need to inject to page in stack
  __set_arg(r, RegIndex::CALLNO, sc.callno);
  for (size_t i = 0; i < sc.nargs; i++) {
    uint64_t value = sc.args[i].is_ptr ? sc.args[i].guest_ptr : sc.args[i].value;
    __set_arg(r, (RegIndex)i, value);
  }

  // XXX: Can we safely inject into either of these - should be possible
  // with some specially-crafted custom return addresses/state for children
  //assert(!IS_CLONE_SC(sc.callno) && !IS_FORK_SC(sc.callno));

  // If this syscall will return *ONCE* we inject into R12-R15 and cleanup on return
  // Otherwise we just inject this syscall and can't get the results

  if (is_noreturn_ && sc.has_retval) {
    std::cerr << "USER ERROR: Syscall " << sc.callno << " is marked noreturn but has a custom retval - incompatable options" << std::endl;
  }


  if (!is_noreturn_) {
    // If this syscall is expected to return, we can add our magic values into registers

    if(IS_NORETURN_SC(sc.callno) || IS_FORK_SC(sc.callno) || IS_CLONE_SC(sc.callno)) {
      std::cerr << "USER ERROR: Syscall " << sc.callno << " is yielded awaiting a return but it's a noreturn" << std::endl;
      assert(0);
      return false; // Don't expect a return, we won't even set user's args. This is fatal
    }

    r.r12 = reinterpret_cast<uint64_t>(SyscallCtx_);
    //r.r13 = r.rip; // XXX on construct we moved rcx into our rip since that's what it is
    r.r13 = r.rcx;
    r.r14 = MAGIC_VALUE;
    r.r15 = r.r12 ^ r.r13;
  }

  assert(set_regs(cpu, &r));
  return !is_noreturn_; // Return true IF we expect a return

  // If we return fales, runtime.,cpp will call on_coopter_finish which
  // will deallocate and destory the coopter
}

  void SyscallCtx_impl::demagic(void* cpu, uint64_t pc) {
    // Restore R12, R13, R14, R15 from orig_regs - this is
    // when we hit a syscall that we've set up from a sysret
    cpu_ = cpu;
    magic_ = -1;
    kvm_regs new_regs = orig_regs_;

    // Do we need to keep rflags? I'm not sure if we can/should
    // With it unset perf_eval N=1 coreutils multicore passes
    // Other tests also don't seem to change with this enabled
    kvm_regs current_regs;
    assert(get_regs(cpu, &current_regs));
    new_regs.rflags = current_regs.rflags; // Keep changes to RFLAGS?

    if (!has_custom_retval()) [[likely]] {
      // Generally we set the retval to the result of the last syscall
      // (i.e., what's currently in RAX before we change registers)
      //kvm_regs current_regs;
      //assert(get_regs(cpu, &current_regs));
      new_regs.rax = current_regs.rax; // We want the process to see the retval of the last syscall!
    } else {
      // But if a user wants, we can also set it to something custom
      new_regs.rax = get_custom_retval();
    }

    if (has_custom_return()) [[unlikely]] {
      // If a user specifies a custom retaddr we can support it
      // though this is untested in the current design
      new_regs.rip = get_custom_return();
    } else {
      // In general we set the RIP to the PC arg which should be the insn after the syscall
      new_regs.rip = pc;
    }

    assert(set_regs(cpu, &new_regs));
  }


void SyscallCtx_impl::at_sysret_redo_syscall(void* cpu, uint64_t sc_pc) {
  // In a sysert we want to go back to the syscall insn at sc_pc.
  //fprintf(fp, "In sysret, we want to want to re-execute syscall insn at %lx, object is at %p\n", sc_pc, this);

  kvm_regs new_regs = orig_regs_;
  cpu_ = cpu;
  new_regs.r12 = reinterpret_cast<uint64_t>(SyscallCtx_);
  new_regs.r13 = sc_pc;
  new_regs.r14 = MAGIC_VALUE_REPEAT;
  new_regs.r15 = new_regs.r12 ^ new_regs.r13;

  // And change our PC to sc_pc by setting RIP directly
  new_regs.rip = sc_pc;


  assert(set_regs(cpu, &new_regs));
}

bool SyscallCtx_impl::translate_gva(uint64_t gva, uint64_t* gpa) {
    return ::translate_gva(cpu_, gva, gpa);
}
bool SyscallCtx_impl::gpa_to_hva(uint64_t gpa, uint64_t *hva) {
    return ::gpa_to_hva(cpu_, gpa, hva);
}
