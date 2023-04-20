#pragma once

//#include "hyde/include/syscall_context.h"
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include <linux/kvm.h>
#include <cassert>

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


class syscall_context_impl {
public:
  syscall_context_impl(void* cpu, syscall_context *ctx, uint64_t orig_rcx, uint64_t orig_r11);
  syscall_context_impl(const syscall_context_impl& other, void* cpu, syscall_context *ctx);
  ~syscall_context_impl();


  uint64_t get_arg(RegIndex i) const;

  void set_coopter(create_coopter_t f) {
    coopter_ = (f)(syscall_context_).h_;
  }

  void set_name(std::string name) {
    name_ = name;
  }

  std::string get_name() {
    return name_;
  }

  #if 0
  void set_child() {
    parent_ = false;
    child_ = true;
  }

  bool is_child() {
    return child_;
  }

  void set_parent() {
    child_ = false;
    parent_ = true;
  }

  bool is_parent() {
    return parent_;
  }
  #endif

  void advance_coopter() {
    assert(coopter_ != nullptr);
    coopter_();
  }

  auto get_coopter_promise() {
    assert(coopter_ != nullptr);
    return coopter_.promise();
  }

  hsyscall* get_orig_syscall() { return orig_syscall_;}

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
    assert(0);
    has_custom_retval_ = true;
    custom_retval_ = retval;
  }

  bool set_syscall(void* cpu, hsyscall sc, bool nomagic);

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

  void* get_cpu() {
    return cpu_;
  }

  void set_child_coopter(create_coopter_t f);

  bool has_child_coopter() {
    return child_coopter_ != nullptr;
  }

  void set_orig(uint64_t orig_rcx, uint64_t orig_r11) {
    orig_rcx_ = orig_rcx;
    orig_r11_ = orig_r11;
  }

  uint64_t get_orig_r11() {
    return orig_r11_;
  }

  uint64_t get_orig_rcx() {
    return orig_rcx_;
  }

  int magic_; // XXX DEBUGGING
  int ctr_; // XXX DEBUGGING
  int last_sc_; // XXX DEBUGGING

private:
  syscall_context *syscall_context_;

  struct kvm_regs orig_regs_; // The original registers when we started simulating the guest process
  bool set_orig_regs(void* cpu);

  hsyscall *orig_syscall_; // The original system call that was about to run in the target process
  coopter_t coopter_; // The coroutine that has taken over the guest process

  // A user can specify a retval to return
  bool has_custom_retval_; // XXX dropped support for this
  uint64_t custom_retval_;

  uint64_t last_sc_retval_;

  // If set, return to a customa ddress post-sc
  bool has_custom_return_;
  uint64_t custom_return_;

  create_coopter_t child_coopter_;

  //bool child_; // True if this is a child process after a fork/clone
  //bool parent_; // True if this is a parent process after a fork/clone
  //uint64_t last_sc_retval; // Return value to be set after simulating a system call

  void* cpu_; // Opaque pointer we use internally
  std::string name_; // Name (full path) of the hyde program

  uint64_t orig_rcx_; // Next PC?
  uint64_t orig_r11_; // Pre-syscall rflags

#if 0
  uint64_t asid;
#endif
};
