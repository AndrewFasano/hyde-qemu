#pragma once

#include <set>
#include <map>
#include <string>
#include "plugin_common.h"

// XXX can we drop this file?

// create_coopt_t functions are called with a bunch of stuff and return a pointer to a function with type SyscallCoroutine(syscall_context*)
//typedef SyscallCoroutine(create_coopt_t)(syscall_context*);
using create_coopt_t = SyscallCoroutine(*)(syscall_context*);

// CPUs that have syscall introspection enabled
std::set<int> introspection_cpus;

// create_coopt_t is function type that is given a few arguments and returns a function pointer function with type create_coopt_t(syscall_context*)
using coopter_f = create_coopt_t*(*)(void*, long unsigned int, long unsigned int, unsigned int);

std::set<long unsigned int> did_seccomp; // Procs that did a seccomp
std::set<syscall_context*> coopted_procs = {}; // Procs that have been coopted
std::set<std::string> pending_exits = {}; // Hyde progs that have requested to exit

// Procs that we expect to return twice - store once in _parents and once in _children
// Pop when we no longer expect
std::set<syscall_context*> double_return_parents = {};
std::set<syscall_context*> double_return_children = {};