#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"
#include <syscall.h>
#include <cstring>

// Set on syscall, looked for on sysret
#define MAGIC_VALUE 0xdeadbeef

// Set on sysret, looked for on syscall - only when repeating
#define MAGIC_VALUE_REPEAT 0xb1ade001

/*
magic1 = 0xdeadbeef             | 0xb1ade000              KVM:R14
magic2 = key                    | key^syscall_pc          KVM:R15
magic3 = unused                 | key                     KVM:R12
magic4 = unused                 | syscall_pc              KVM:R13
*/

#define SKIP_FORK


static uint64_t global_ctr = 0;
static uint64_t N = (uint64_t)-1;

FILE *fp = NULL;

struct Data {
  int magic;
  kvm_regs orig_regs;
  bool parent_ret_pending;
  bool child_call_pending;
  bool force_retval;
  uint64_t retval;
  int pending;
  int ctr;

  // Initialize and orig_regs based on CPU
  Data(void* cpu) : magic(0x12345678), orig_regs(), parent_ret_pending(false), child_call_pending(false), force_retval(false), pending(-1), ctr(0), refcount(1) {
      assert(get_regs(cpu, &orig_regs));
  }

  // Create a new instance with the same orig_regs as the old - XXX drop this?
  Data(const Data& other) : magic(0x12345678), parent_ret_pending(false), child_call_pending(false), force_retval(false), retval(0), pending(-1), ctr(0), refcount(1) {
      std::memcpy(&orig_regs, &other.orig_regs, sizeof(kvm_regs));
  }

  // Helper methods
  void addRef() {
    refcount++;
  }

  void release() {
    refcount--;
    if (refcount == 0) {
        magic = -1;
        //fprintf(fp, "Freeing %p\n", this);
        delete this;
    }
  }

  bool is_fork(int callno) const {
    return callno == SYS_fork || callno == SYS_vfork;
  }

  void handle_fork(kvm_regs& new_regs, uint64_t pc) {
    new_regs.rcx = pc - 2; // Re-exec current syscall
    addRef();
    parent_ret_pending = true;
    child_call_pending = true;
  }

  void update_regs_for_injected_syscall(kvm_regs& new_regs, uint64_t new_callno, uint64_t pc) {
    new_regs.rax = new_callno;
    // TODO: args?
    new_regs.rcx = pc - 2; // Re-exec current syscall
  }


  void restore_registers(kvm_regs &new_regs) {
    // Restore R12, R13, R14, R15 from orig_regs
    new_regs.r12 = orig_regs.r12;
    new_regs.r13 = orig_regs.r13;
    new_regs.r14 = orig_regs.r14;
    new_regs.r15 = orig_regs.r15;
  }

  void update_regs_for_nop(uint64_t pc, uint64_t new_retval) {
    orig_regs.rax = retval;
    orig_regs.rcx = pc;
    orig_regs.rax = SYS_getpid;
    force_retval = true;
    retval = new_retval;
  }

  void update_regs_for_original_syscall(kvm_regs& new_regs, uint64_t pc) {
    //new_regs.rax = orig_regs.rax; // new_regs is based on orig_regs
    new_regs.rcx = pc;
  }

  void inject_syscall(void* cpu, int callno, kvm_regs& new_regs) {
    // At a syscall: set magic values so we can detect and clenaup on return
    new_regs.rax = (uint64_t)callno;
    new_regs.r14 = MAGIC_VALUE;
    new_regs.r15 = reinterpret_cast<uint64_t>(this);

    pending = (int)new_regs.rax; // Callno, won't overflow an int
    ctr++;

    assert(set_regs(cpu, &new_regs));
  }

  void at_sysret_redo_syscall(void* cpu, uint64_t sc_pc, kvm_regs& new_regs) {
    // In a sysert we want to go back to the syscall insn at sc_pc.

    new_regs.r12 = reinterpret_cast<uint64_t>(this);
    new_regs.r13 = sc_pc;
    new_regs.r14 = MAGIC_VALUE_REPEAT;
    new_regs.r15 = new_regs.r12 ^ new_regs.r13;

    // And change our PC to sc_pc as well via RCX. This works, we used it previously:
    // https://github.com/AndrewFasano/hhyde-qemu/blob/6b15778ff2e2f56e3b3311f2a4a3b608026e4ba5/accel/kvm/hyde.cpp#L539
    new_regs.rip = sc_pc;
  }

private:
  int refcount;
};


Runtime::LoadedPlugin::~LoadedPlugin() = default;

// On syscall stick a host ptr in r15
// On sysret use host ptr to cleanup and examine register delta

bool get_magic_values(uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15, uint64_t *out_key, uint64_t *out_pc) {
  if (r14 != MAGIC_VALUE_REPEAT) return false;

  if ((r12 ^ r13) != r15) {
    printf("XXX detected key mutation (ignore): R14 is %lx R12 is %lx and R13 is %lx. Expected %lx but have %lx\n", r14, r12, r13, r12 ^ r13, r15);
    return false;
  }


  //printf("Valid magic, out_key is %lx, out_pc is %lx\n", r12, r13);
  *out_key = r12;
  *out_pc = r13;
  return true;
}

bool Runtime::handle_reinjection(void* cpu, uint64_t pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  uint64_t out_key;
  uint64_t out_pc;

  if (!get_magic_values(r12, r13, r14, r15, &out_key, &out_pc)) {
    // No magic present
    return false;
  }

  if (out_pc != pc) {
    printf("XXX blocking moved key - key specifies %lx but we're at %lx\n", out_pc, pc);
    // It's valid, but not for this PC - bail, we're probably in a syscall handler
    return false;
  }

  // Alright, we want to inject a syscall here based off our out_key
  Data* target = reinterpret_cast<Data*>(out_key);

  // Sanity checks - it's valid and not waiting on a syscall
  assert(target->magic == 0x12345678);
  assert(target->pending == -1);

  //printf("After injection with %lx we see getpid returned %ld\n", reinterpret_cast<uint64_t>(target), rax);

  target->ctr++;

  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs)); // Get current registers
  target->restore_registers(new_regs); // Restore R12-R15 to original values
  target->inject_syscall(cpu, target->orig_regs.rax, new_regs); // Clobber R14/R15 with syscall->sysret magic values

  return true; // We're injecting here - don't fall back to the normal handler that could start a new injection
}

void Runtime::on_syscall(void* cpu, uint64_t next_pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  Data* target = nullptr;

  int callno = (int)rax;

  if (callno ==  SYS_rt_sigreturn ||
      callno == SYS_clone || callno == SYS_clone3 ||
      callno == SYS_exit || callno == SYS_exit_group ||
      callno == SYS_execve || callno == SYS_execveat ||
      callno == SYS_fork || callno == SYS_vfork) { /* These last two should be changed if we try to disable SKIP_FORK */
    return;
  }

  uint64_t pc = next_pc-2;

  if (!handle_reinjection(cpu, pc, rax, r12, r13, r14, r15)) {
    // If we had to advance a coroutine and all that we've already done it.
    // Instead, we're here so it's our first time with this one. Let's co-opt if we want to

    if (global_ctr++ % N != 0) [[likely]] {
      return; // We're not interested
    }


    target = new Data(cpu);
    //printf("SYSCALL at %lx: new injection %lx, \n", pc, reinterpret_cast<uint64_t>(target));

    kvm_regs new_regs;
    assert(get_regs(cpu, &new_regs)); // Get current registers
    target->inject_syscall(cpu, SYS_getpid, new_regs); // Clobber RAX/R14/R15 with syscall->sysret magic values so we inject getpid
  }
}

void Runtime::on_sysret(void* cpu, uint64_t pc, uint64_t retval, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  assert(r14 == MAGIC_VALUE && "VMM incorrectly triggered on_sysret");

  Data* target = (Data*)r15;
  assert(target->magic == 0x12345678);

  assert(target->pending != -1);
  target->pending = -1;

  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs));

  if (target->ctr > 1) {
    //printf("SYSRET at %lx - all done, original sc (%lld) returns %lld\n", pc, target->orig_regs.rax, new_regs.rax);
    // All done with injection. Restore original registers
    uint64_t retval = (target->force_retval) ? target->retval : new_regs.rax;

    // Restore original R14/R15 values and decrement refcount
    new_regs.r14 = target->orig_regs.r14;
    new_regs.r15 = target->orig_regs.r15;
    target->release();

    new_regs.rax = retval; // Only changes it if we had force_retval
  } else {
    //printf("SYSRET at %lx - more to come, go back to %lx\n", pc, pc-2);
    // We have another syscall to run! Need to go back to pc-2 and ensure we only run at the right time
    target->at_sysret_redo_syscall(cpu, pc-2, new_regs); // Updates new_regs
  }

  assert(set_regs(cpu, &new_regs)); // Apply new_regs
}

bool Runtime::load_hyde_prog(void* cpu, std::string path) {
  //fp = fopen("/tmp/sc.txt","w");

  // Get N from env and convert to int. On error abort
  N = (uint64_t)(getenv("N") ? atoi(getenv("N")) : -1);

  if (N == (uint64_t)-1) {
    printf("WARNING: [HyDE] N not set - not injecting getpid\n\n\n");
  }
  return N != (uint64_t)-1;
}

bool Runtime::unload_all(void* cpu) {
  return true;
}

bool Runtime::unload_hyde_prog(void* cpu, std::string path) {
  return true;
}

// Implement the custom deleter
void PluginDeleter::operator()(Plugin *plugin) const {
  //fclose(fp); // Uhh?
  delete plugin;
}