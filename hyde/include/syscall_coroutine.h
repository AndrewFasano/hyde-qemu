#pragma once

#include <coroutine>
#include <functional>
#include <stdexcept>

#include "hsyscall.h"

// HydeCoro is our tempalted coroutine we'll use for
// SyscallCoroutines and SyscCoroHelpers
enum class ExitStatus;

class SyscallCtx;

template <typename T, typename R>
struct HydeCoro {
  struct promise_type {
    T value_;
    R retval;

    ~promise_type() {}

    HydeCoro<T, R> get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() { std::terminate(); }


    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(T value) {
      value_ = value;
      return {};
      //printf("Yielding a value\n");
    }

    void return_value(R value) {
      retval = value;
      value_ = {0};
    };
  };

  std::coroutine_handle<promise_type> h_;
};

// The syscCoro type is a coroutine that yields hsyscall objects and returns an exit Status
using SyscallCoroutine = HydeCoro<hsyscall, ExitStatus>;

// Yields hsyscalls, returns an int - for helper functions
using SyscCoroHelper = HydeCoro<hsyscall, int>;

// coopter_t is a coroutine handle to SyscallCoroutine coroutines
using coopter_t = std::coroutine_handle<SyscallCoroutine::promise_type>;

// Pointer to a function that, when called, initializes a SyscallCoroutine?
using create_coopter_t = std::function<SyscallCoroutine(SyscallCtx*)>;
