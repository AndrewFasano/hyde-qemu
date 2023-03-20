#ifndef HYDE_H
#define HYDE_H

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <asm/unistd.h> // Syscall numbers
#include <cstring>
#include <iostream> // Just for cout
#include <string>
#include <sys/mman.h> // for mmap flags
#include <type_traits>
#include <unistd.h>
#include <vector>
#include <linux/kvm.h>
#include <cassert>
#include <tuple>
#include <utility>
#include <coroutine>

#include "hyde_common.h" // Sets debug+windows, typedefs hsyscall
#include "hyde_macros.h" // set_ARGX - can we replace those?


void dump_syscall(hsyscall h);

int getregs(asid_details*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(asid_details*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);

// Debug helper function
void dump_sc(struct kvm_regs r);
void dump_sc_with_stack(asid_details* a, struct kvm_regs r);
void dump_regs(struct kvm_regs r);

// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscCoro(asid_details*)
typedef SyscCoro(create_coopt_t)(asid_details*);
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

bool translate_gva(asid_details *r, uint64_t gva, uint64_t* hva);
// Coroutine helpers - HyDE programs can yield_from these and the helpers can inject
// more syscalls if they'd like
SyscCoro ga_memcpy_one(asid_details* r, void* out, uint64_t gva, size_t size);
SyscCoro ga_memcpy(asid_details* r, void* out, uint64_t gva, size_t size);
SyscCoro ga_memread(asid_details* r, void* out, uint64_t gva, size_t size);
SyscCoro ga_memwrite(asid_details* r, uint64_t gva, void* in, size_t size);
//SyscCoro ga_memmove(asid_details* r, uint64_t dest, void* src, size_t size);
SyscCoro ga_map(asid_details* r, uint64_t gva, void** host, size_t min_size);

// Series of templates to deduce the size of a variadic list of arguments
// This is used so we can calculate the necessary stack size in guest
// memory that we will use for copying hsyscall arguments into the guest's memory

// Handle non-array, non-pointer types
template <typename T>
auto deduce_type_and_size_impl(T&& arg, std::false_type, std::false_type) {
    //return std::make_pair(&arg, sizeof(T));
    return std::make_pair(&arg, 0); // XXX: Do *not* count the size of these types
}

// Handle pointer types
template <typename T>
auto deduce_type_and_size_impl(T* arg, std::false_type, std::true_type) {
    return std::make_pair(arg, sizeof(std::remove_pointer_t<T>));
}

// Handle array types
template <typename T, size_t N>
auto deduce_type_and_size_impl(T (&arr)[N], std::true_type, std::false_type) {
    return std::make_pair(arr, sizeof(T) * N);
}

template <typename T>
auto deduce_type_and_size(T&& arg) {
    return deduce_type_and_size_impl(std::forward<T>(arg), 
                                     std::is_array<std::remove_reference_t<T>>{}, 
                                     std::is_pointer<std::remove_reference_t<T>>{});
}

template <typename... Args>
auto deduce_types_and_sizes(Args&&... args) {
    return std::tuple_cat(std::make_tuple(deduce_type_and_size(std::forward<Args>(args)))...);
}


template <typename... Args>
constexpr size_t accumulate_stack_sizes(std::tuple<Args...> tuple) {
    size_t sum = 0;
    // Round up to 32-bits - this matches how we actually allocate these things later
    std::apply([&sum](auto... args) { (..., (sum += args.second ? (args.second + (32 - (args.second % 32))): 0 ) ); }, tuple); // Padding for non-zero sized elements
    return sum;
}

template <long SyscallNumber, typename Function, typename... Args>
hsyscall unchecked_build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //printf("Inject syscall %ld with %ld args, total size %ld\n", SyscallNumber, sizeof...(Args), TotalSize);
    // Now generate an hsyscall object with the syscall number, arguments, and number of args
    hsyscall s {
      .callno = SyscallNumber
    };
 
    // Populate s->args with each of the elements in args and set s->nargs to the number of arguments.
    s.nargs = 0;
    auto set_args = [&s](auto &&arg) {
      assert(s.nargs < sizeof(s.args) / sizeof(s.args[0])); // Make sure we don't go OOB (is this off by 1?)
      s.args[s.nargs++].value = (uint64_t)arg;
    };
    (set_args(args), ...);
    return s;
}

/* Given a system call number, a function pointer to the system call, and a list of arguments, allocate, initialize
 * and return na hsyscall object
 */
template <long SyscallNumber, typename Function, typename... Args>
hsyscall build_syscall(Function syscall_func, uint64_t guest_stack, Args... args) {
    //using ReturnType = decltype(syscall_func(std::declval<Args>()...));
    using ExpectedArgsTuple = std::tuple<typename std::remove_reference<Args>::type...>;
    using ActualArgsTuple = std::tuple<typename std::remove_reference<decltype(std::declval<Args>())>::type...>;

    // Ensure that the specified arguments match the syscall signature
    // Note that every syscall for linux returns a long so we don't need to typecheck that
    static_assert(std::is_same_v<ExpectedArgsTuple, ActualArgsTuple>,
                  "Argument types do not match the syscall signature.");

    return unchecked_build_syscall<SyscallNumber>(syscall_func, guest_stack, args...);
}

/* Yield_from runs a coroutine, yielding the syscalls it yields, then finally returns a value that's co_returned from there */
#define yield_from(f, ...) \
  ({ \
    auto h = f(__VA_ARGS__).h_; \
    auto &promise = h.promise(); \
    uint64_t rv = 0; \
    while (!h.done()) { \
        co_yield promise.value_; \
        h(); /* Advance the other coroutine  */ \
        rv = promise.retval; \
    } \
    h.destroy(); \
    rv; \
  })

void map_one_arg(int idx, hsyscall *pending, uint64_t *stack_addr, auto args) {
  // Calculate how argument idx should be mapped to the guest stack. Update pending->args[idx] and stack_addr
  uint64_t this_size = (uint64_t)args.second;
  if (this_size) {
    uint64_t padded_size = this_size + (32 - (this_size % 32)); // 32-bit aligned
    pending->args[idx].is_ptr = true;
    pending->args[idx].guest_ptr = *stack_addr;
    pending->args[idx].size = this_size;
    *stack_addr += padded_size; // Shift stack address
  }
} 

template <typename... Args>
SyscCoro map_args_to_guest_stack(asid_details* details, uint64_t stack_addr, hsyscall *pending, std::tuple<Args...> tuple) {
  // Given a tuple of arguments with types and sizes, map those arguments, with concrete
  // pointer values stored in pending->args to the guest stack

  // Our fold expression can't be a coroutine, but we're a coroutine. In the map_one_arg function
  // that we call on each element, we'll identify host->guest mappings we need to do and update pending->args
  pending->nargs = 0;
  std::apply(
    [pending, &stack_addr](auto... args) {
      // Size is args.second? If size isn't 0, we should map. If size is 0 we can skip?
      (..., (map_one_arg(pending->nargs++, pending, &stack_addr, args)));
    },
  tuple);

  // Now look through pending->args and actually do the memory mappings
  for (int i = 0; i < pending->nargs; i++) {
    if (pending->args[i].is_ptr) {
      //printf("map host %lx to guest %lx, size %d\n", pending->args[i].value, pending->args[i].guest_ptr, pending->args[i].size);
      yield_from(ga_memwrite, details, pending->args[i].guest_ptr, (void*)pending->args[i].value, pending->args[i].size); // XXX we want this, just need kvm
    }
  }
  co_return 0;
}

template <typename... Args>
SyscCoro map_args_from_guest_stack(asid_details* details, uint64_t stack_addr, hsyscall *sc, Args&&... args) {
  // We just ran syscall sc, iterate through it's arguments, identifying poitners and yield syscalls to map them back

  for (int i = 0; i < sc->nargs; i++) {
    if (sc->args[i].is_ptr) {
      //printf("map guest %lx to host %lx, size %d\n", sc->args[i].guest_ptr, sc->args[i].value, sc->args[i].size);
      yield_from(ga_memread, details, (void*)sc->args[i].value, sc->args[i].guest_ptr, sc->args[i].size); // XXX we want this, just need kvm
    }
  }

  co_return 0;
}

/* Pair of macros to 1) get a mapping of {type, arg size} and 2) sum up the arg size values returned by the first */
#define get_arg_types_sizes(...) deduce_types_and_sizes(__VA_ARGS__);
#define calculate_size(_argTuple) accumulate_stack_sizes(_argTuple);

/* Helper macro to be used by SyscCoro coroutines. Build an hsyscall using the given function name,
 * yield that hsyscall (which will cause the details object to update place a return in last_sc_ret),
 * free the heap-allocated hsyscall, and finally provide the caller with the result of the simulated
 * syscall which was set in details->last_sc_ret.
 */
#define yield_syscall(details, func, ...) ({                                                                  \
  auto arg_types_tup = get_arg_types_sizes(__VA_ARGS__);                                                      \
  size_t total_size = calculate_size(arg_types_tup);                                                          \
  size_t padded_total_size = total_size + (1024 - (total_size % 1024));                                       \
  /*printf("Total stack size is %lu, padded to %lu\n", total_size, padded_total_size);*/                      \
  uint64_t guest_stack = 0;                                                                                   \
  hsyscall s = build_syscall<SYS_##func>(::func, guest_stack, __VA_ARGS__);                                   \
  if (total_size > 0)                                                                                         \
  { /* We need some stack space for the arguments for this syscall. Allocate it! */                           \
    /*printf("AUTO-ALLOCATE %d bytes (rounded up from %d)\n", padded_total_size, total_size);*/               \
    co_yield unchecked_build_syscall<SYS_mmap>(::mmap, 0, 0, padded_total_size,                               \
                                                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);  \
    guest_stack = details->last_sc_retval; /* TODO: error checking?*/                                         \
    /* Now, for each argument, map it!*/                                                                      \
    yield_from(map_args_to_guest_stack, details, guest_stack, &s, arg_types_tup);                                      \
  }                                                                                                           \
  co_yield s;                                                                                                 \
  int rv = details->last_sc_retval;                                                                           \
  if (total_size > 0)                                                                                         \
  { /* We previously allocated some stack space for this syscall, sync it back, then free it */               \
    yield_from(map_args_from_guest_stack, details, guest_stack, &s, arg_types_tup);                                    \
    co_yield (unchecked_build_syscall<SYS_munmap>(::munmap, 0, padded_total_size));                           \
  }                                                                                                           \
  rv;                                                                                                         \
})

/* Build and yield a syscall, return it's result. Do *not* auto allocate and map arguments. */
#define yield_syscall_raw(details, func, ...) ({         \
  co_yield unchecked_build_syscall<SYS_##func>(::func, 0, __VA_ARGS__); \
  details->last_sc_retval;                                    \
})

#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return -1;};

// Type signature for a function *hyde programs* must implement. Implemenations should
// returns a pointer to a local (extern C) coroutine function if the syscall should be
// co-opted, otherwise NULL
extern "C" {
  create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);
}

#endif