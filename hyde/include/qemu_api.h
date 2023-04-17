#pragma once

// Used in kvm-cpus.c? Nope, just in KVM?
//#define R14_INJECTED 0xdeadbeef
//void enable_syscall_introspection(void* cpu, int idx);
//void disable_syscall_introspection(void* cpu, int idx);

#ifdef __cplusplus
extern "C" {
#endif
    // QEMU requests disabling HyDE. Should be called foreach cpu
    bool kvm_unload_hyde(void *cpu, int idx);

    // QEMU requests loading a HyDE program. Should be called foreach cpu
    bool kvm_load_hyde_capability(const char* path, void *cpu, int idx);

    // QEMU requests unloading a HyDE program. Should be called foreach cpu
    bool kvm_unload_hyde_capability(const char* path, void *cpu, int idx);

    // QEMU informs HyDE that a syscall has been detected
    void on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15);

    // QEMU informs HyDE that a sysret has been detected
    void  on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15);
#ifdef __cplusplus
}
#endif
