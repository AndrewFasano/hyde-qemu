#pragma once

#include "hyde_common.h"
#include "syscall_coroutine.h"
#include <linux/kvm.h>
#include <cassert>

#define IS_NORETURN_SC(x)(x == __NR_execve || \
                          x == __NR_execveat || \
                          x == __NR_exit || \
                          x == __NR_exit_group || \
                          x == __NR_rt_sigreturn)

#define IS_CLONE_SC(x)(x == __NR_clone || x == __NR_clone3)
#define IS_FORK_SC(x)(x == __NR_fork || x == __NR_vfork)

// Pretty print kvm_regs
static inline void pretty_print_regs(kvm_regs regs) {
  printf("\trax: %llx, rbx: %llx, rcx: %llx, rdx: %llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
  printf("\trsi: %llx, rdi: %llx, rsp: %llx, rbp: %llx\n", regs.rsi, regs.rdi, regs.rsp, regs.rbp);
  printf("\tr8: %llx, r9: %llx, r10: %llx, r11: %llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
  printf("\tr12: %llx, r13: %llx, r14: %llx, r15: %llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
  printf("\trip: %llx, rflags: %llx\n", regs.rip, regs.rflags);
}

// Given two kvm_regs print only fields that are different using a macro
#define PRINT_DIFF(regs1, regs2, field) \
  if (regs1.field != regs2.field) { \
    printf("\t" #field ": %llx -> %llx\n", regs1.field, regs2.field); \
  }

// Now use the macro, for each field in the struct
static inline void pretty_print_diff_regs(kvm_regs regs1, kvm_regs regs2) {
  PRINT_DIFF(regs1, regs2, rax);
  PRINT_DIFF(regs1, regs2, rbx);
  PRINT_DIFF(regs1, regs2, rcx);
  PRINT_DIFF(regs1, regs2, rdx);
  PRINT_DIFF(regs1, regs2, rsi);
  PRINT_DIFF(regs1, regs2, rdi);
  PRINT_DIFF(regs1, regs2, rsp);
  PRINT_DIFF(regs1, regs2, rbp);
  PRINT_DIFF(regs1, regs2, r8);
  PRINT_DIFF(regs1, regs2, r9);
  PRINT_DIFF(regs1, regs2, r10);
  PRINT_DIFF(regs1, regs2, r11);
  PRINT_DIFF(regs1, regs2, r12);
  PRINT_DIFF(regs1, regs2, r13);
  PRINT_DIFF(regs1, regs2, r14);
  PRINT_DIFF(regs1, regs2, r15);
  PRINT_DIFF(regs1, regs2, rip);
  PRINT_DIFF(regs1, regs2, rflags);
}


class SyscallCtx_impl {
public:
  SyscallCtx_impl(void* cpu, SyscallCtx *ctx);
  //SyscallCtx_impl(const SyscallCtx_impl& other, void* cpu, SyscallCtx *ctx);
  ~SyscallCtx_impl();


  /* Get an arg from the original syscall*/
  uint64_t get_arg(int i) const;

  // Set an arg in the original syscall */
  void set_arg(int i, uint64_t new_val) const;

  /* Get the original syscall. May have been modified by calls to set_arg */
  hsyscall* get_orig_syscall() { return orig_syscall_;}

  void set_coopter(create_coopter_t f) {
    coopter_ = (f)(SyscallCtx_).h_;
  }

  void set_name(std::string name) {
    name_ = name;
  }

  std::string get_name() {
    return name_;
  }

  void advance_coopter() {
    assert(coopter_ != nullptr);
    coopter_();
  }

  auto get_coopter_promise() {
    assert(coopter_ != nullptr);
    return coopter_.promise();
  }

  bool is_coopter_done() { return coopter_.done(); }

  bool has_custom_retval() {
     return has_custom_retval_;
  }

  uint64_t get_custom_retval() {
     assert(has_custom_retval_);
     return custom_retval_;
  }

  void set_last_rv(uint64_t retval) {
    last_sc_retval_ = retval;
  }

  uint64_t get_last_rv() {
    return last_sc_retval_;
  }

  void set_custom_retval(uint64_t retval) {
    /* Pass a different return value back to process after this injected SC
     * only meaningful for the last syscall in a sequence */
    has_custom_retval_ = true;
    custom_retval_ = retval;
  }

  /* At a syscall instruction, set hsyscall sc to cpu and
    be sure we catch it on cleanup */
 bool inject_syscall(void* cpu, hsyscall sc);

  /* We're reinjecting - restore original R12-R15 before
    XXX this might be pointless  */
  void restore_magic_regs(void* cpu, kvm_regs &new_regs);

  /* At a sysret instruction, set new_regs up to rerun the syscall at sc_pc */
  void at_sysret_redo_syscall(void* cpu, uint64_t sc_pc, kvm_regs& new_regs);

  bool has_custom_return() {
    return has_custom_return_;
  }

  void set_custom_return(uint64_t addr) {
      has_custom_return_ = true;
      custom_return_ = addr;
  }

  uint64_t get_custom_return() {
      assert(has_custom_return_);
      return custom_return_;
  }

  kvm_regs get_orig_regs() {
    return orig_regs_;
  }

  bool translate_gva(uint64_t gva, uint64_t* gpa);
  bool gpa_to_hva(uint64_t gpa, uint64_t* hva);

  int magic_; // XXX DEBUGGING
  int ctr_; // XXX DEBUGGING

private:
  /* Get an arg from the original register state*/
  uint64_t get_arg_(RegIndex i) const;


  SyscallCtx *SyscallCtx_;

  // The original registers when we started coopting guest process
  struct kvm_regs orig_regs_;

  // orig syscall may be modified with calls to set_arg
  hsyscall *orig_syscall_; // The original system call that was about to run in the target process
  coopter_t coopter_; // The coroutine that has taken over the guest process

  // A user can specify a retval to return
  bool has_custom_retval_; // XXX dropped support for this
  uint64_t custom_retval_;

  uint64_t last_sc_retval_;

  // If set, return to a custom address post-sc
  bool has_custom_return_;
  uint64_t custom_return_;

  void* cpu_; // XXX TODO: We probably need a different cpu object when we swap CPUs?
              // How can we internally update this as we go?

  std::string name_; // Name (full path) of the hyde program
};
