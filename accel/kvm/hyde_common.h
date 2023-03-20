#include <coroutine>

#ifndef HYDE_COMMON_H
#define HYDE_COMMON_H

struct hsyscall_arg {
  uint64_t value; // host_pointer OR constant
  bool is_ptr; // if true, value is a host pointer
  uint64_t guest_ptr; // ignored if !is_ptr
  unsigned int size; // ignored if !is_ptr
};

// hsyscall is a struct that represents a system call that we will simulate execution of.
// Before the syscall is simulated, it should be populated with callno, nargs, and args.
// After the syscall is simulated, retval will store the return value and has_retval will be set to true.
typedef struct {
  uint64_t callno; // System call number
  unsigned int nargs; // Number of arguments
 hsyscall_arg args[6]; // Arguments for the syscall

  // After we simulate
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

// Coroutine that yield objects of type T and finally returns a uint64_t
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

// The syscCoro type is a coroutine that yields hsyscall objects and returns a uint64_t
typedef HydeCoro<hsyscall> SyscCoro;
// coopter_t is a coroutine handle to SyscCoro coroutines
typedef std::coroutine_handle<HydeCoro<hsyscall>::promise_type> coopter_t;

/* This structure stores details about a given process that we are co-opting.
 * It contains a pointer to the coroutine that is simulating the process's execution.
 * It also contains a pointer to the original system call that the process was executing.
 * Finally, it contains a pointer to the original registers that the process was executing.
*/
typedef struct _asid_details {
  coopter_t coopter; // The coroutine that is simulating the process's execution
  struct kvm_regs orig_regs; // The original registers when we started simulating the guest process
  hsyscall *orig_syscall; // The original system call that was about to run in the target process
  void* cpu; // Opaque pointer we use internally
  long unsigned int last_sc_retval; // Return value to be set after simulating a system call

  uint64_t asid;

  uint64_t orig_rcx; // RCX and R11 values before the original requested system call
  uint64_t orig_r11;
  bool use_orig_regs; // If set, after coopter finishes we' restore RCX/R11 to their pre-syscall values

  unsigned long custom_return; // If set to a non-zero value, we will set the guest's program counter to this address after coopter finishes

  //std::function<void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)> *on_ret; // Unused
} asid_details;


// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(asid_details*)
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);


#endif