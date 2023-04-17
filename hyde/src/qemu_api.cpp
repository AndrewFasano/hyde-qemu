#include <cassert>
#include "hyde/include/internal.h"
#include "hyde/src/runtime_instance.h"
#include "hyde/include/qemu_api.h" // Need for extern C style on_syscall/sysret 


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
    //runtime.unload_all(cpu, idx);;

    assert(0 && "NYI");
#if 0
    assert(cpu != nullptr);
    //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
#endif
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
  assert(0 && "NYI"); 
#if 0
  printf("Unload %s on cpu %d\n", path, idx);
  return try_unload_coopter(std::string(path), cpu, idx);
#endif
}

void on_syscall(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int callno, long unsigned int asid, long unsigned int pc, long unsigned int orig_rcx, long unsigned int orig_r11, long unsigned int r14, long unsigned int r15) {
    return get_runtime_instance().on_syscall(cpu, cpu_id, fs, callno, asid, pc, orig_rcx, orig_r11, r14, r15);
}

void on_sysret(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int retval, long unsigned int asid, long unsigned int pc, long unsigned int r14, long unsigned int r15) {
    return get_runtime_instance().on_sysret(cpu, cpu_id, fs, retval, asid, pc, r14, r15);
}