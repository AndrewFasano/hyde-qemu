#pragma once

// Used in kvm-cpus.c? Nope, just in KVM?
#define R14_INJECTED 0xdeadbeef

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
    void on_syscall(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int callno, long unsigned int asid, long unsigned int pc, long unsigned int orig_rcx, long unsigned int orig_r11, long unsigned int r14, long unsigned int r15);

    // QEMU informs HyDE that a sysret has been detected
    void on_sysret(void *cpu, unsigned long cpu_id, long unsigned int fs, long unsigned int retval, long unsigned int asid, long unsigned int pc, long unsigned int r14, long unsigned int r15);
#ifdef __cplusplus
}
#endif
