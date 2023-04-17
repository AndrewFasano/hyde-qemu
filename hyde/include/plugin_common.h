#pragma once

#include "hyde/include/syscall_context.h"
#include "hyde/include/syscall_coroutine.h"
#include "runtime.h"
#include <memory>
#include <functional>

using SyscallHandler = std::function<SyscallCoroutine(syscall_context*)>;
using ExitStatus = int;

// Enum for argument indexing into kvm_regs struct
enum class RegIndex {
    ARG0 = 0, ARG1 = 1, ARG2 = 2,
    ARG3 = 3, ARG4 = 4, ARG5 = 5,
    CALLNO = 6, RET = 7, // Both refer to rax, treated as same elsewhere
};

class Plugin {
public:
  virtual ~Plugin() {}

  // Implement this method to provide syscall handlers
  virtual void register_syscall_handlers(Runtime* runtime) = 0;
};

extern "C" {
  // Plugin entry point function prototype
  Plugin* create_plugin();
}