#include <cassert>
#include <linux/kvm.h>
#include "internal.h"
#include "hyde/src/runtime_instance.h"
#include "qemu_api.h" // "extern C" for on_syscall/sysret 

// This param is from our custom kernel in uapi/linux/kvm.h // #define KVM_HYDE_TOGGLE      _IOR(KVMIO,   0xbb, bool)
// this evalutes to 8001aebb
#define KVM_HYDE_TOGGLE (int)0x8001aebb

// get hwaddr typedef
#include "qemu/compiler.h"
#include "exec/hwaddr.h"

static bool hyde_enabled=false;

extern "C" {
    // Can't just include kvm header, it has too much stuff in it.
    // But we're in the same compilation unit, so we can just declare it
    extern int kvm_vcpu_ioctl(void *cpu, int type, ...);
    extern int kvm_vcpu_ioctl_pause_vm(void *cpu, int type, ...);
    int kvm_host_addr_from_physical_memory(hwaddr gpa, hwaddr *phys_addr);
}

void enable_syscall_introspection(void* cpu, int idx) {
    assert(cpu != nullptr);
    //printf("Enable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl_pause_vm(cpu, KVM_HYDE_TOGGLE, 1) == 0);
    hyde_enabled = true;
}

void disable_syscall_introspection(void* cpu, int idx) {
    assert(cpu != nullptr);
    //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
    assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
    hyde_enabled = false;
}

bool kvm_unload_hyde(void *cpu, int idx) {
    // Monitor request hits here. This can't work this simply though
    // because if any are actively coopted, we need to wait for them to finish

    if (!hyde_enabled) return false;

    get_runtime_instance().unload_all(cpu);
    //printf("Disable syscall introspection on CPU %d at %p\n", idx, cpu);
    if (cpu != nullptr) {
        // May be called during shutdown in which case we get a chance to print results, but we don't toggle here
        // because cpu is null
        assert(kvm_vcpu_ioctl(cpu, KVM_HYDE_TOGGLE, 0) == 0);
    }
    hyde_enabled = false;
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

void on_syscall(void* cpu, uint64_t pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
    return get_runtime_instance().on_syscall(cpu, pc, rax, r12, r13, r14, r15);
}

void on_sysret(void* cpu, uint64_t pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
    return get_runtime_instance().on_sysret(cpu, pc, rax, r12, r13, r14, r15);
}

bool can_translate_gva(void* cpu, uint64_t gva) {
    struct kvm_translation trans = { .linear_address = gva };

    // Requesting the translation shouldn't ever fail, even though
    // the translated result might be that the translation failed
    assert(kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &trans) == 0);

    // Translation ok if valid and != -1
    return (trans.valid && trans.physical_address != (unsigned long)-1);
}

/* Given a GVA, try to translate it to a host address.
 * return indicates success. If success, host address
 * will be set in hva argument. */
bool translate_gva(void* cpu, uint64_t gva, uint64_t* hva) {
    if (!can_translate_gva(cpu, gva)) {
    return false;
    }
    // Duplicate some logic from can_translate_gva so we can get the physaddr here
    struct kvm_translation trans = { .linear_address = (__u64)gva };
    assert(kvm_vcpu_ioctl(cpu, KVM_TRANSLATE, &trans) == 0);

    assert(kvm_host_addr_from_physical_memory(trans.physical_address, (uint64_t*)hva) == 1);
    return true;
}

bool gpa_to_hva(void* cpu, uint64_t gpa, uint64_t* hva) {
    return kvm_host_addr_from_physical_memory(gpa, (uint64_t*)hva) == 1;
}
bool get_regs(void*cpu, kvm_regs* regs) {
    int rv = kvm_vcpu_ioctl(cpu, KVM_GET_REGS, regs);
    if (rv != 0) printf("ERROR: %d\n", rv);
    return rv == 0;
}

bool set_regs(void*cpu, kvm_regs* regs) {
    int rv = kvm_vcpu_ioctl(cpu, KVM_SET_REGS, regs);
    if (rv != 0) {
        printf("ERROR: %d\n", rv);
    }
    return rv == 0;
}