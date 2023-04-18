#pragma once

#include "runtime.h"
#include "syscall_context.h"
#include "syscall_coroutine.h"
#include <functional>
#include <memory>

using SyscallHandler = std::function<SyscallCoroutine(syscall_context*)>;

enum class ExitStatus {
    SUCCESS = 0, // OK & do nothing
    FINISHED = 1, // OK & unload HyDe Program
    SINGLE_FAILURE = -1, // Failed & do nothing
    FATAL = -2, // Failed & unload HyDe Program
};


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