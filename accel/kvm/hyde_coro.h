#ifndef HYDE_CORO_H
#define HYDE_CORO_H

#include <coroutine>
#include <functional>
#include "hyde_common.h"

// Based off the coroutine tutorial here https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html
#if 0
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
#endif


//typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;


template <typename T>
struct HydeCoro {
  struct promise_type {
    T value_;
    uint64_t retval;

    ~promise_type() {
      //printf("Coro destroyed\n");
    }

    HydeCoro<T> get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() {}

    // Regular yield, returns an hsyscall value
    std::suspend_always yield_value(T value) {
      value_ = value;
      return {};
      //printf("Yielding a value\n");
    }

    //void return_value(T const& value) {
    void return_value(int value) {
      retval = value;
      value_ = {0};
      //printf("Returning a value: %ld\n", retval);
    };
  };

  std::coroutine_handle<promise_type> h_;
};




typedef HydeCoro<hsyscall> SyscCoro;
typedef std::coroutine_handle<HydeCoro<hsyscall>::promise_type> coopter_t;
//typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;


#endif