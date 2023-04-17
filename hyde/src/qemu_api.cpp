#include <cassert>
#include "hyde/include/internal.h"
#include "hyde/src/runtime_instance.h"
#include "hyde/include/qemu_api.h" // "extern C" for on_syscall/sysret 

// This param is from our custom kernel in uapi/linux/kvm.h
// #define KVM_HYDE_TOGGLE      _IOR(KVMIO,   0xbb, bool)
// this evalutes to 8001aebb
#define KVM_HYDE_TOGGLE 0x8001aebb

extern "C" {
    // Can't just include kvm header, it has too much stuff in it.
    // But we're in the same compilation unit, so we can just declare it
    extern int kvm_vcpu_ioctl(void *cpu, int type, ...);
    extern int kvm_vcpu_ioctl_pause_vm(void *cpu, int type, ...);
}

void enable_syscall_introspection(void* cpu, int idx) {
    assert(cpu != nullptr);
    //printf("Enable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl_pause_vm(cpu, KVM_HYDE_TOGGLE, 1) == 0);
}

void disable_syscall_introspection(void* cpu, int idx) {
    assert(cpu != nullptr);
    //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
}

bool kvm_unload_hyde(void *cpu, int idx) {
    // Monitor request hits here. This can't work this simply though
    // because if any are actively coopted, we need to wait for them to finish

    assert(cpu != nullptr);
    get_runtime_instance().unload_all(cpu);
    //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
  return true;
}

bool kvm_load_hyde_capability(const char* path, void *cpu, int idx) {
    if (introspection_cpus.count(idx) == 0) {
        enable_syscall_introspection(cpu, idx);
        introspection_cpus.insert(idx);
        //printf("Enabled syscall introspection on CPU %d at %p\n", idx, cpu);
    }

    return get_runtime_instance().load_hyde_prog(cpu, std::string(path));
}

bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx) {
    return get_runtime_instance().unload_hyde_prog(cpu, std::string(path));
}

void on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
    return get_runtime_instance().on_syscall(cpu, pc, callno, rcx, r11, r14, r15);
}

void  on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {
    return get_runtime_instance().on_sysret(cpu, pc, retval, r15, r15);
}