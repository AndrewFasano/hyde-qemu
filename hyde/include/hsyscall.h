#pragma once

#include <stdint.h>

struct hsyscall_arg {
  uint64_t value; // host_pointer OR constant
  bool is_ptr; // if true, value is a host pointer
  uint64_t guest_ptr; // ignored if !is_ptr, otherwise the guest pointer that this host pointer is mapped to
  unsigned int size; // ignored if !is_ptr, otherwise the size of the struct pointed to
  bool copy_out; // if is_ptr and unset, we won't copy the data back out of the guest
  //bool copy_in; // if is_ptr and set, we won't copy the data into the guest NYI

  hsyscall_arg() :
    value(0),
    is_ptr(false),
    guest_ptr(0),
    size(0),
    copy_out(false) {};

  hsyscall_arg(uint64_t value):
    value(value),
    is_ptr(false),
    guest_ptr(0),
    size(0),
    copy_out(false) {};
};

/* hsyscall is a struct that represents a system call along with its arguments.
 * An hsyscall can be injected into the guest so long as callno, nargs and args[0...nargs-1] are set.
 * After an hsyscall is injected, retval will bet set to the return value of the syscall and has_retval will be set to true.
*/
struct hsyscall {
  bool consumed; // Did we inject it already - just for debugging
  uint64_t callno; // System call number
  unsigned int nargs; // Number of arguments
  hsyscall_arg args[6]; // Arguments for the syscall

  // After we run
  uint64_t retval;
  bool has_retval;

  hsyscall() :

    callno(0),
    nargs(0),
    retval(0),
    has_retval(false) {}

  hsyscall(uint64_t callno) :
    consumed(false),
    callno(callno),
    nargs(0),
    retval(0),
    has_retval(false) {}

  void set_retval(uint64_t value) {
    has_retval = true;
    retval = value;
  }

  void set_args(unsigned int n, uint64_t* new_args) {
    for (unsigned int i = 0; i < n && i < 6; i++) {
      args[i] = hsyscall_arg(new_args[i]);
    }
    nargs = n;
  }
};
