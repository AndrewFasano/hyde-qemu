#ifndef HYDE_CORO_H
#define HYDE_CORO_H

#include <coroutine>
#include <functional>
#include "hyde_common.h"

// Based off the coroutine tutorial here https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
struct SyscCoroutine {
  struct promise_type {
    hsyscall value_;

    ~promise_type() { }

    SyscCoroutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}

    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(hsyscall value) {
      value_ = value;
      return {};
    }

    void return_void() {}

  };

  std::coroutine_handle<promise_type> h_;
};


//typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;


template <typename T>
struct HyDeCoro {
  struct promise_type {
    T value_;
    uint64_t retval_;

    ~promise_type() { }

    SyscCoroutine get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}

    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(hsyscall value) {
      value_ = value;
      return {};
    }

    void return_void() {
        retval_ = 0;
    }
    void return_bool(bool v) {
        retval_ = (uint64_t)v;
    }
    void return_int(int v) {
        retval_ = (uint64_t)v;
    }
    void return_long(long v) {
        retval_ = (uint64_t)v;
    }
  };

  std::coroutine_handle<promise_type> h_;
};

typedef std::coroutine_handle<HydeCoro<hsyscall>::promise_type> coopter_t;

#endif