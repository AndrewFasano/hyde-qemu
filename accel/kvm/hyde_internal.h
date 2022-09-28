#ifndef HYDE_HELPERS_H
#define HYDE_HELPERS_H

#include <linux/types.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include "hyde.h"

// This param is from our custom kernel in uapi/linux/kvm.h
// #define KVM_HYDE_TOGGLE      _IOR(KVMIO,   0xbb, bool)
// this evalutes to 8001aebb
#define KVM_HYDE_TOGGLE 0x8001aebb

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);
extern "C" int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);
//typedef std::pair<bool(*)(void*, long unsigned int), SyscCoroutine(*)(asid_details*)> coopter_pair;

std::map<std::string, coopter_f*> coopters; // function which returns coroutine or NULL
std::map<long unsigned int, asid_details*> active_details; // asid->details
std::set<long unsigned int> did_seccomp;

#endif
