#pragma once

#include <linux/kvm.h>

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

    // Outgoing API: HyDE requests something from QEMU
    bool translate_gva(void* cpu, uint64_t gva, uint64_t* gpa);
    bool can_translate_gva(void* cpu, uint64_t gva);
    bool gpa_to_hva(void* cpu, uint64_t gpa, uint64_t* hva);
    bool get_regs(void* cpu, struct kvm_regs *outregs);
    bool set_regs(void* cpu, struct kvm_regs *inregs);

#ifdef __cplusplus
}
#endif
