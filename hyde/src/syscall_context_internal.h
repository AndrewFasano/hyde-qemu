#pragma once

#include "hyde/include/syscall_context.h"
#include "hyde/include/plugin_common.h"
#include <linux/kvm.h>

class syscall_context_impl {
public:
  syscall_context_impl(int syscall_number);
  ~syscall_context_impl();

  int get_syscall_number() const;
  struct kvm_regs get_orig_regs() const;
  // Internal functions accessible only by the runtime

private:
  int syscall_number_;
  struct kvm_regs orig_regs_; // The original registers when we started simulating the guest process

#if 0
  coopter_t coopter; // The coroutine that is simulating the process's execution
  std::string name; // Name (full path) of the hyde program

  hsyscall *orig_syscall; // The original system call that was about to run in the target process
  void* cpu; // Opaque pointer we use internally
  uint64_t last_sc_retval; // Return value to be set after simulating a system call
  bool child; // True if this is a child process

  uint64_t asid;

  uint64_t orig_rcx; // RCX and R11 values before the original requested system call
  uint64_t orig_r11;
  bool use_orig_regs; // If set, after coopter finishes we' restore RCX/R11 to their pre-syscall values

  unsigned long custom_return; // If set to a non-zero value, we will set the guest's program counter to this address after coopter finishes
  // Other private members
#endif
};
