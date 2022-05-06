#ifndef HYDE_HELPERS_H
#define HYDE_HELPERS_H

#include <linux/types.h>
#include <vector>
#include <map>
#include "hyde.h"

extern "C" int kvm_vcpu_ioctl(void *cpu, int type, ...);
extern "C" int kvm_host_addr_from_physical_physical_memory(__u64, __u64*);
typedef std::pair<bool(*)(void*, long unsigned int), SyscCoroutine(*)(asid_details*)> coopter_pair;

std::vector<coopter_pair> coopters; // Pair of bool() which indicates if coopter should start and coopter
std::map<long unsigned int, asid_details*> active_details; // asid->details

#endif
