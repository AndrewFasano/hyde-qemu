#pragma once

//#include "hyde/include/syscall_context.h"
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include <linux/kvm.h>
#include <cassert>

class syscall_context_impl {
public:
  syscall_context_impl(void* cpu, syscall_context *ctx);
  syscall_context_impl(const syscall_context_impl& other, void* cpu, syscall_context *ctx);
  ~syscall_context_impl();


  uint64_t get_arg(RegIndex i) const;

  void set_coopter(create_coopter_t f) {
    coopter_ = (f)(syscall_context_).h_;
  }

  void set_name(std::string name) {
    name_ = name;
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

  create_coopter_t child_coopter_;

  //bool child_; // True if this is a child process after a fork/clone
  //bool parent_; // True if this is a parent process after a fork/clone
  //uint64_t last_sc_retval; // Return value to be set after simulating a system call

  void* cpu_; // Opaque pointer we use internally
  std::string name_; // Name (full path) of the hyde program

#if 0
  uint64_t asid;
#endif
};
