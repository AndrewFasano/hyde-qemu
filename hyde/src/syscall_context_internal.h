#pragma once

//#include "hyde/include/syscall_context.h"
#include "hyde/include/plugin_common.h"
#include <linux/kvm.h>
#include <cassert>

class syscall_context_impl {
public:
  syscall_context_impl(void* cpu, syscall_context *ctx);
  syscall_context_impl(const syscall_context_impl& other) {
    syscall_context_ = other.syscall_context_;
    orig_regs_ = other.orig_regs_;
    orig_syscall_ = other.orig_syscall_;
    coopter_ = other.coopter_;
    has_custom_retval_ = other.has_custom_retval_;
    custom_retval_ = other.custom_retval_;
    last_sc_retval_ = other.last_sc_retval_;
    has_custom_return_ = other.has_custom_return_;
    custom_return_ = other.custom_return_;
    child_ = other.child_;
  }
  ~syscall_context_impl();

  uint64_t get_arg(RegIndex i) const;

  void set_coopter(create_coopter_t f) {
    coopter_ = (f)(syscall_context_).h_;
  }

  void set_child() {
    child_ = true;
  }

  bool is_child() {
    return child_;
  }

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

  bool set_syscall(void* cpu, hsyscall sc);

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

  kvm_regs get_orig_regs() { return orig_regs_; }

private:
  syscall_context *syscall_context_;

  struct kvm_regs orig_regs_; // The original registers when we started simulating the guest process
  bool set_orig_regs(void* cpu);

  hsyscall *orig_syscall_; // The original system call that was about to run in the target process
  coopter_t coopter_; // The coroutine that has taken over the guest process

  // A user can specify a retval to return
  bool has_custom_retval_;
  uint64_t custom_retval_;

  uint64_t last_sc_retval_;

  // If set, return to a customa ddress post-sc
  bool has_custom_return_;
  uint64_t custom_return_;

  bool child_; // True if this is a child process after a fork/clone
  //uint64_t last_sc_retval; // Return value to be set after simulating a system call

#if 0
  std::string name; // Name (full path) of the hyde program

  void* cpu; // Opaque pointer we use internally

  uint64_t asid;

#endif
};
