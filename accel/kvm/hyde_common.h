#ifndef HYDE_H
#define HYDE_H

#include <sys/types.h>
#include <cstring>
#include <string>
#include <linux/kvm.h>
#include <coroutine>
#include <cstdint>
#include <stdexcept>
#include <cassert>

// This file provides common datatypes used by both KVM-hyde and hyde programs.
// Additionally it provides prototypes for KVM-hyde functions that may be used by hyde programs.

//#define WINDOWS
//#define HYDE_DEBUG


struct hsyscall_arg {
  uint64_t value; // host_pointer OR constant
  bool is_ptr; // if true, value is a host pointer
  uint64_t guest_ptr; // ignored if !is_ptr, otherwise the guest pointer that this host pointer is mapped to
  unsigned int size; // ignored if !is_ptr, otherwise the size of the struct pointed to
  bool copy_out; // if is_ptr and unset, we won't copy the data back out of the guest
  //bool copy_in; // if is_ptr and set, we won't copy the data into the guest NYI
};

/* hsyscall is a struct that represents a system call along with its arguments.
 * An hsyscall can be injected into the guest so long as callno, nargs and args[0...nargs-1] are set.
 * After an hsyscall is injected, retval will bet set to the return value of the syscall and has_retval will be set to true.
*/
typedef struct {
  uint64_t callno; // System call number
  unsigned int nargs; // Number of arguments
 hsyscall_arg args[6]; // Arguments for the syscall

  // After we run
  uint64_t retval;
  bool has_retval;
} hsyscall;

// Enum for coroutine exit status
enum class ExitStatus {
    SUCCESS = 0, // OK & do nothing
    FINISHED = 1, // OK & unload HyDe Program
    SINGLE_FAILURE = -1, // Failed & do nothing
    FATAL = -2, // Failed & unload HyDe Program
};


// Coroutine that yield objects of type T and finally returns an ExitStatus
// To be used by HyDE programs
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
    void unhandled_exception() {}

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
typedef HydeCoro<hsyscall, ExitStatus> SyscCoro;

// Yields hsyscalls, returns an int - for helper functions
typedef HydeCoro<hsyscall, int> SyscCoroHelper;
// coopter_t is a coroutine handle to SyscCoro coroutines
typedef std::coroutine_handle<HydeCoro<hsyscall, ExitStatus>::promise_type> coopter_t;

/* This structure stores details about a given process that we are co-opting.
 * It contains a pointer to the coroutine that is simulating the process's execution.
 * It also contains a pointer to the original system call that the process was executing.
 * Finally, it contains a pointer to the original registers that the process was executing.
*/
struct asid_details {
  coopter_t coopter; // The coroutine that is simulating the process's execution
  std::string name; // Name (full path) of the hyde program
  struct kvm_regs orig_regs; // The original registers when we started simulating the guest process
  hsyscall *orig_syscall; // The original system call that was about to run in the target process
  void* cpu; // Opaque pointer we use internally
  uint64_t last_sc_retval; // Return value to be set after simulating a system call

  uint64_t asid;

  uint64_t orig_rcx; // RCX and R11 values before the original requested system call
  uint64_t orig_r11;
  bool use_orig_regs; // If set, after coopter finishes we' restore RCX/R11 to their pre-syscall values

  unsigned long custom_return; // If set to a non-zero value, we will set the guest's program counter to this address after coopter finishes

  //std::function<void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)> *on_ret; // Unused
};

// Enum for argument indexing into kvm_regs struct
enum class RegIndex {
    ARG0 = 0, ARG1 = 1, ARG2 = 2,
    ARG3 = 3, ARG4 = 4, ARG5 = 5,
    CALLNO = 6, RET = 7, // Both refer to rax, treated as same elsewhere
};

// Function to get the argument value by index
inline uint64_t get_arg(struct kvm_regs s, RegIndex idx) {
    switch (idx) {
        case RegIndex::CALLNO:
        case RegIndex::RET: return s.rax;
        case RegIndex::ARG0: return s.rdi;
        case RegIndex::ARG1: return s.rsi;
        case RegIndex::ARG2: return s.rdx;
        case RegIndex::ARG3: return s.r10;
        case RegIndex::ARG4: return s.r8;
        case RegIndex::ARG5: return s.r9;
        default: throw std::runtime_error("Invalid register index");
    }
}

// Function to set the argument value by index given an hsyscall_arg
inline void set_arg(struct kvm_regs& s, RegIndex idx, hsyscall_arg arg) {
    // XXX: callno and ret can't be pointers
    uint64_t value = arg.is_ptr ? arg.guest_ptr : arg.value;
    switch (idx) {
        case RegIndex::ARG0: s.rdi = value; break;
        case RegIndex::ARG1: s.rsi = value; break;
        case RegIndex::ARG2: s.rdx = value; break;
        case RegIndex::ARG3: s.r10 = value; break;
        case RegIndex::ARG4: s.r8 = value; break;
        case RegIndex::ARG5: s.r9 = value; break;
        default: throw std::runtime_error("Invalid register index");
    }
}

// CALLNO/RET are set as uint64_ts, not hsyscall_args
inline void set_arg(struct kvm_regs& s, RegIndex idx, uint64_t value) {
    switch (idx) {
        case RegIndex::CALLNO:
        case RegIndex::RET: s.rax = value; break;
        default: throw std::runtime_error("Invalid register index");
    }
}


// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(asid_details*)
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

bool translate_gva(asid_details *r, uint64_t gva, uint64_t* hva); // Coroutine helpers use this for translation
uint64_t kvm_translate(void *cpu, uint64_t gva);
int kvm_host_addr_from_physical_memory_ext(uint64_t gpa, uint64_t *phys_addr);
int getregs(asid_details *r, struct kvm_regs *regs);

// I've never seen this fail, but it feels safer than an assert?
#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return ExitStatus::SINGLE_FAILURE;};

// Type signature for a function *hyde programs* must implement. Implemenations should
// returns a pointer to a local (extern C) coroutine function if the syscall should be
// co-opted, otherwise NULL
extern "C" {
  create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);
}

#endif