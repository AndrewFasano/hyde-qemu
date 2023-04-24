#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "hsyscall.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"
#include <syscall.h>
#include <cstring>
#include <algorithm>

// Set on syscall, looked for on sysret
#define MAGIC_VALUE 0xdeadbeef

// Set on sysret, looked for on syscall - only when repeating
#define MAGIC_VALUE_REPEAT 0xb1ade001

/*
        syscall->ret              sysret->syscall
magic1 = 0xdeadbeef             | 0xb1ade000              KVM:R14
magic2 = key^sysret_pc          | key^syscall_pc          KVM:R15
magic3 = key                    | key                     KVM:R12
magic4 = sysret_pc              | syscall_pc              KVM:R13
*/

#define SKIP_FORK
static uint64_t global_ctr = 0;
static uint64_t N = (uint64_t)-1;

//FILE *fp = NULL;

// XXX this needs to merge with struct syscall_context from hyde_common
struct Data {
  int magic;
  kvm_regs orig_regs;
  bool parent_ret_pending;
  bool child_call_pending;
  bool force_retval;
  uint64_t retval;
  int pending;
  int ctr;
  hsyscall* orig_syscall;
  coopter_t coopter;

  // Initialize and orig_regs based on CPU
  Data(void* cpu) : magic(0x12345678), orig_regs(), parent_ret_pending(false), child_call_pending(false), force_retval(false), pending(-1), ctr(0), refcount(1) {
      assert(get_regs(cpu, &orig_regs));
      orig_syscall = new hsyscall(orig_regs.rax);
      uint64_t args[6];
      for (int i = 0; i < 6; i++) {
        args[i] = get_arg(details->orig_regs, (RegIndex)i);
      }
      orig_syscall->set_args(6, args);
  }

  // Create a new instance with the same orig_regs as the old - XXX drop this?
  //Data(const Data& other) : magic(0x12345678), parent_ret_pending(false), child_call_pending(false), force_retval(false), retval(0), pending(-1), ctr(0), refcount(1) {
  //    std::memcpy(&orig_regs, &other.orig_regs, sizeof(kvm_regs));
  //}

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

/*
  bool is_fork(int callno) const {
    return callno == SYS_fork || callno == SYS_vfork;
  }

  void handle_fork(kvm_regs& new_regs, uint64_t pc) {
    new_regs.rcx = pc - 2; // Re-exec current syscall
    addRef();
    parent_ret_pending = true;
    child_call_pending = true;
  }

  void update_regs_for_nop(uint64_t pc, uint64_t new_retval) {
    orig_regs.rax = retval;
    orig_regs.rcx = pc;
    orig_regs.rax = SYS_getpid;
    force_retval = true;
    retval = new_retval;
  }

  void update_regs_for_injected_syscall(kvm_regs& new_regs, uint64_t new_callno, uint64_t pc) {
    // TODO: this would need to also support arguments
    new_regs.rax = new_callno;
    new_regs.rcx = pc - 2; // Re-exec current syscall
  }
*/

  void restore_registers_for_reinjection(kvm_regs &new_regs) {
    // Restore R12, R13, R14, R15 from orig_regs - this is 
    // when we hit a syscall that we've set up from a sysret
    new_regs.r12 = orig_regs.r12;
    new_regs.r13 = orig_regs.r13;
    new_regs.r14 = orig_regs.r14;
    new_regs.r15 = orig_regs.r15;
  }

  void inject_syscall(void* cpu, int callno, kvm_regs& new_regs) {
    // At a syscall: set magic values so we can detect and clenaup on return
    //fprintf(fp, "Injecting syscall %d at pc %llx. Object is at %p\n", callno, new_regs.rip, this);
    new_regs.rax = (uint64_t)callno;
    new_regs.r12 = reinterpret_cast<uint64_t>(this);
    new_regs.r13 = new_regs.rcx; // next instruction? Uhh
    new_regs.r14 = MAGIC_VALUE;
    new_regs.r15 = new_regs.r12 ^ new_regs.r13;

    pending = (int)new_regs.rax; // Callno, won't overflow an int
    ctr++;

    assert(set_regs(cpu, &new_regs));
  }

  void at_sysret_redo_syscall(void* cpu, uint64_t sc_pc, kvm_regs& new_regs) {
    // In a sysert we want to go back to the syscall insn at sc_pc.
    //fprintf(fp, "In sysret, we want to want to re-execute syscall insn at %lx, object is at %p\n", sc_pc, this);

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
    //fprintf(fp, "XXX blocking moved key - key specifies %lx but we're at %lx. Not using target %lx\n", out_pc, pc, out_key);
    // It's valid, but not for this PC - bail, we're probably in a syscall handler
    return false;
  }

  // Alright, we want to inject a syscall here based off our out_key
  Data* target = reinterpret_cast<Data*>(out_key);

  // Sanity checks - it's valid and not waiting on a syscall
  assert(target->magic == 0x12345678);
  assert(target->pending == -1);

  //fprintf(fp, "At syscall after injection with target %p, getpid returned %ld, now we're going to set up original syscall to run %lld\n", target, rax, target->orig_regs.rax);

  target->ctr++;

  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs)); // Get current registers
  target->restore_registers_for_reinjection(new_regs); // Restore R12-R15 to original values
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
    // Instead, we're here so this is our first chance to inject on this syscall.

    // Find a coopter for this sycall if one is registered. -1 beats anything else
    create_coopter_t *f = NULL;
    if (syscall_handlers_.find(-1) != syscall_handlers_.end()) {
      // We have a catchall, pretend callno is -1 so we use it
      callno = -1;
    }

    if (syscall_handlers_.find(callno) != syscall_handlers_.end()) {
      // Get & store original registers before we run the coopter's first iteration
      f = &syscall_handlers_[callno];
    }

    if (f == NULL) return; // No coopter for this syscall

    std::string name; // Which hyde program is this for?A
    // Look through coopters_map and find the key that has this callno
    for (auto it = coopters_map_.begin(); it != coopters_map_.end(); it++) {
      // does this hyde program's coopted syscall vector contain callno?
      if (std::find(it->second.begin(), it->second.end(), callno) != it->second.end()) {
        name = it->first;
        break;
      }
    }

    target = new Data(cpu);
    //fprintf(fp, "SYSCALL at %lx: new injection with target at %p, \n", pc, target);

    // Create original syscall using info from regs
    coopted_procs_.insert(target);

    target->coopter = (*f)(details).h_;
    details->name = name;



  }
}

void Runtime::on_sysret(void* cpu, uint64_t pc, uint64_t retval, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  assert(r14 == MAGIC_VALUE && "VMM incorrectly triggered on_sysret");

  if ((r12 ^ r13) != r15) {
    // Yep, this happens sometimes when N>1
    //printf("Woah - on sysret have unexpected magic:\n");
    //printf("r12: %lx\n", r12);
    //printf("r13: %lx\n", r13);
    //printf("r15: %lx vs exprected %lx \n", r15, r12 ^ r13);
    //printf("XXX IGNORING???\n");
    return;
  }

  if (r13 != pc) {
    printf("XXX On sysret expected pc %lx but have %lx - ignoring (?) \n", r13, pc);
    return;
  }

  //fprintf(fp, "SYSRET with target 0x%lx\n", r12);

  Data* target = (Data*)r12;
  //if (target->magic != 0x12345678) {
  //  fprintf(fp, "FATAL bad magic for target at %p\n", target);
  //  fflush(fp);
  //}
  assert(target->magic == 0x12345678);

  assert(target->pending != -1);
  target->pending = -1;

  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs));

  if (target->ctr > 1) {
    //fprintf(fp, "SYSRET at %lx - all done, original sc (%lld) returns %lld, let's clean up target %p\n", pc, target->orig_regs.rax, new_regs.rax, target);
    // All done with injection. Restore original registers
    uint64_t retval = (target->force_retval) ? target->retval : new_regs.rax;

    // Restore original R12-15 values and decrement refcount
    new_regs.r12 = target->orig_regs.r12;
    new_regs.r13 = target->orig_regs.r13;
    new_regs.r14 = target->orig_regs.r14;
    new_regs.r15 = target->orig_regs.r15;
    target->magic = -1;
    target->release();

    new_regs.rax = retval; // Only changes it if we had force_retval
  } else {
    //fprintf(fp, "SYSRET at %lx - injected syscall returns %llx. Target is at %p\n", pc, new_regs.rax, target);
    // We have another syscall to run! Need to go back to pc-2 and ensure we only run at the right time
    target->at_sysret_redo_syscall(cpu, pc-2, new_regs); // Updates new_regs
  }

  assert(set_regs(cpu, &new_regs)); // Apply new_regs
}

bool Runtime::load_hyde_prog(std::string path) {
  // introspection is enabled and program should be unique by the time we get here

  void* handle = dlopen(path.c_str(), RTLD_NOW);
  if (handle == NULL) {
    std::cerr  << "Could not open capability at " << path << ": " << dlerror() << std::endl;
    return false;
  }

  // Get init_plugin function and call it
  auto init_plugin = reinterpret_cast<PluginInitFn>(dlsym(handle, "init_plugin"));
  if (init_plugin == nullptr) {
      std::cerr << "Failed to get init function: " << dlerror() << std::endl;
      dlclose(handle);
      return 1;
  }
  std::unordered_map<int, create_coopter_t> handlers;
  bool rv = init_plugin(handlers);

  if (!rv) return false;

  // If plugin returned true, take it's updates to the handlers map
  // Raise errors on duplicate key conflicts between hyde programs
  // ALso store the mapping from programs -> hooked syscalls

  std::vector<int> hooked_scs;
  for (auto it = handlers.begin(); it != handlers.end(); ++it) {
    int key = it->first;
    create_coopter_t handler = it->second;

    // If we already have a handler for this key, error
    if (syscall_handlers_.count(key)) {
      std::cerr << "ERROR: Two HyDE programs request to coopt syscall " << key << std::endl;
      return false;
    }

    // Otherwise, store the handler and that this hyde program uses it
    syscall_handlers_[key] = handler;
    hooked_scs.push_back(key);

    std::cout << "HyDE program " << path << " will coopt SYS_" << key  << std::endl;
  }
  coopters_map_[path] = hooked_scs;

  return true;
}

bool Runtime::unload_all(void* cpu) {
  // Called at qemu shutdown - good place to log results / call uninit methods on loaded programs
  //std::cerr << "Finished after " << global_ctr << " syscalls (injected every " << N << ")" << std::endl;

  // TODO: for each program, call unload
  std::cerr << "TODO cleanly unload all hyde prgraoms" << std::endl;
  //disable_syscall_introspection(cpu, idx);

  return true;
}

bool Runtime::unload_hyde_prog(void* cpu, std::string path) {
  if (!coopters_map_.count(path)) {
    std::cerr << "HyDE program " << path << " has not been loaded" << std::endl;
    return false;
  }

  // Remove all the coopted syscalls that this program set up
  // Now we won't intercept future calls to these
  for (auto it = coopters_map_[path].begin(); it != coopters_map_[path].end(); ++it) {
    int key = *it;
    syscall_handlers_.erase(key);
  }
  // XXX TODO: if we have no active coopters and no hyde programs loaded we can disable HyDE now

  // If this hyde program has no active coopters, we can now erase it and possibly disablre
  // otherwise we have to wait until they all finish
  //coopters_map.erase(path);
  //if (coopters_map.empty()) {
  //  disable_syscall_introspection(cpu, idx);
  //}
  return true;
}

// Implement the custom deleter, necessary for some reason
void PluginDeleter::operator()(Plugin *plugin) const {
  delete plugin;
}