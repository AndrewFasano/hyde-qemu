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
    bool did_return = false;

    ~promise_type() { }

    HydeCoro<T> get_return_object() {
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
      did_return = false;
      //printf("Yielding a value\n");
    }

    //void return_value(T const& value) {
    void return_value(int value) {
      retval = value;
      value_ = {0};
      did_return = true; // Do we need this? Can't tell if these are staying alive too long or there are just lots
      //printf("Returning a value: %ld\n", retval);
    };
  };

  std::coroutine_handle<promise_type> h_;
};

typedef HydeCoro<hsyscall> SyscCoro;
typedef std::coroutine_handle<HydeCoro<hsyscall>::promise_type> coopter_t;
//typedef std::coroutine_handle<SyscCoroutine::promise_type> coopter_t;


#endif