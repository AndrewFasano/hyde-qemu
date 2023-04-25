#include <stdio.h>
#include <assert.h>
#include "hyde_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "hsyscall.h"
#include "syscallctx_internal.h"
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

Runtime::LoadedPlugin::~LoadedPlugin() = default;

bool get_magic_values(uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15, uint64_t *out_key, uint64_t *out_pc) {
  if (r14 != MAGIC_VALUE_REPEAT) return false;

  if ((r12 ^ r13) != r15) {
    printf("XXX detected key mutation (ignore): R14 is %lx R12 is %lx and R13 is %lx. Expected %lx but have %lx\n", r14, r12, r13, r12 ^ r13, r15);
    return false;
  }

  *out_key = r12;
  *out_pc = r13;
  return true;
}

SyscallCtx* Runtime::get_reinject_ctx(void* cpu, uint64_t pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  uint64_t out_key;
  uint64_t out_pc;

  if (!get_magic_values(r12, r13, r14, r15, &out_key, &out_pc)) {
    // No magic present
    return NULL;
  }

  if (out_pc != pc) {
    // It's valid, but not for this PC - bail, we're probably in a syscall handler
    return NULL;
  }

  // Alright, we want to inject a syscall here based off our out_key
  return reinterpret_cast<SyscallCtx*>(out_key);

}

void Runtime::on_syscall(void* cpu, uint64_t next_pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  int callno = (int)rax;

  if (callno == SYS_rt_sigreturn ||
      callno == SYS_clone || callno == SYS_clone3 ||
      callno == SYS_exit || callno == SYS_exit_group ||
      callno == SYS_execve || callno == SYS_execveat ||
      callno == SYS_fork || callno == SYS_vfork) { [[unlikely]] /* These last two should be changed if we try to disable SKIP_FORK */
    return;
  }

  uint64_t pc = next_pc-2;

  // If we've already coopted this process, get a handle to our target state
  SyscallCtx* target = get_reinject_ctx(cpu, pc, rax, r12, r13, r14, r15);

  // Otherwise, it's just a normal guest syscall. If we have any registered
  // create_coopter_t functions, let them co-opt. Otherwise we leave it alone
  if (target == nullptr) {
    create_coopter_t *f = NULL;
    if (syscall_handlers_.find(-1) != syscall_handlers_.end()) {
      // If we have a catchall, set callno to -1 so we select it
      callno = -1;
    }
    if (syscall_handlers_.find(callno) != syscall_handlers_.end()) {
      f = &syscall_handlers_[callno];
    }

    if (f == NULL) return; // No coopter for this syscall - all done

    std::string name; // Which hyde program is this for?
    // Look through coopters_map and find the key that has this callno
    for (auto it = coopters_map_.begin(); it != coopters_map_.end(); it++) {
      // does this hyde program's coopted syscall vector contain callno?
      if (std::find(it->second.begin(), it->second.end(), callno) != it->second.end()) {
        name = it->first;
        break;
      }
    }

    target = new SyscallCtx(cpu);
    //printf("SYSCALL at %lx: new injection with target at %p, \n", pc, target);

    target->pImpl->set_coopter(*f);
    target->pImpl->set_name(name);

    // Track that we have an active coopter running - this is important for safely cleaning up if a program unloads
    coopted_procs_.insert(target);
  }

  // Now we have to have a target, new or old. First make sure it's valid (sanity checks for debugging)
  assert(target->pImpl->magic_ == 0x12345678);
  target->pImpl->ctr_++; // DEBUGGING increment each time we inject

  // Now we need to actually inject our syscall from the coopter, it's in promise.value_
  auto promise = target->pImpl->get_coopter_promise();

  if (target->pImpl->is_coopter_done()) [[unlikely]] {
    // In the syscall, coopter can't be done - would happen if a user cooped and yielded nothing. Should use SDK instead
    std::cerr << "USER ERROR: Coopter injects no syscalls, not even original " << std::endl;
    assert(0);
    return;
  }

  //printf("INJECT: with ctr=%d\n", target->pImpl->ctr_);
  //promise.value_.pprint();

  // Inject the provided syscall!
  if (!target->pImpl->inject_syscall(cpu, promise.value_)) {
    // Returns false if we can't track it (noreturn)
    // In that case we need to cleanup now - note coopter will never advance here
    // Kinda makes sense, if you yield exit, what would you expect?
    coopted_procs_.erase(target);
    delete target;
  }
}

void Runtime::on_sysret(void* cpu, uint64_t pc, uint64_t retval, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15) {
  assert(r14 == MAGIC_VALUE && "VMM incorrectly triggered on_sysret");

  if ((r12 ^ r13) != r15 || r13 != pc) [[unlikely]] {
    // Not ours - ignore
    return;
  }
  //fprintf(fp, "SYSRET with target 0x%lx\n", r12);

  SyscallCtx* target = (SyscallCtx*)r12;
  assert(target->pImpl->magic_ == 0x12345678);

  // Provide retval and advance coroutine
  target->pImpl->set_last_rv(retval);
  target->pImpl->advance_coopter();

  // XXX: Do we need new_regs at all? Can we just use orig?
  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs));
  // In the case of !done, we clobber new_regs R12-R15, leaving the rest alone (inc RAX)
  // In the case of done, we clobbere new_regs R12-R15, leaving the rest alone except RAX on cusotm
  // Would orig_regs !{R12-R15} ever change? Probably not?


  if (!target->pImpl->is_coopter_done()) {
    // We have another syscall to run! Need to go back to pc-2 and ensure we only run at the right time
    //printf("Bring it back now y'all - %p needs rexec of %lx\n", target, pc-2);
    target->pImpl->at_sysret_redo_syscall(cpu, pc-2, new_regs);
    return; // Updated registers
  }

  auto promise = target->pImpl->get_coopter_promise();
  ExitStatus result = promise.retval;

  //fprintf(fp, "SYSRET at %lx - all done, original sc (%lld) returns %lld, let's clean up target %p\n", pc, target->orig_regs.rax, new_regs.rax, target);
  // All done with injection. Restore original registers
  uint64_t new_retval = (target->pImpl->has_custom_retval()) ? target->pImpl->get_custom_retval() : new_regs.rax;
  uint64_t retaddr = target->pImpl->has_custom_return() ? target->pImpl->get_custom_return() : pc; // XXX pc or new_regs.rip?

  // Restore original R12-15 values and decrement refcount
  target->pImpl->restore_magic_regs(cpu, new_regs);
  target->pImpl->magic_ = -1;
  std::string name = target->pImpl->get_name();
  delete target; // XXX if we try handling forks this will need to be more

  new_regs.rax = new_retval; // Only changes it if we had force_retval
  new_regs.rip = retaddr; // Only changes it if we had custom_return

  assert(set_regs(cpu, &new_regs)); // Apply new_regs

  // Based on result, update state for the whole hyde program
  switch (result) {
    case ExitStatus::FATAL:
      printf("[HyDE] Fatal error in %s\n", name.c_str());
      [[fallthrough]];
    case ExitStatus::FINISHED:
      //if (!pending_exits.contains(name)) {
      //  printf("[HyDE] Unloading %s on cpu %d\n", name.c_str(), 0);
      //  //try_unload_coopter(details->name, cpu, 0); // XXX multicore guests, need to do for all CPUs?
      //  pending_exits.insert(name);
      //}
      break;

    case ExitStatus::SINGLE_FAILURE:
      printf("[HyDE] Warning %s experienced a non-fatal failure\n", name.c_str());
      break;

    case ExitStatus::SUCCESS:
      // Nothing to do
      break;
  }

    // For each pending exit (i.e., coopter that is done), check if any of the injections we're tracking are it
#if 0
  for (auto it = pending_exits.begin(); it != pending_exits.end(); ) {
    // Check if any coopters are still active
    bool active = false;
    for (const auto &kv : coopted_procs) {
      if (kv->name == *it) {
        active = true;
        break;
      }
    }

    if (!active) {
      if (try_unload_coopter(*it, cpu, 0)) { // Safe to unload now
        printf("[HyDE] Unloaded %s\n", it->c_str());
        //it = std::erase_if(pending_exits, [&](const auto& name) { return name == *it; });
        //it = std::remove_if(pending_exits.begin(), pending_exits.end(), [&](const auto& name) { return name == *it; });
        it = pending_exits.erase(it);
        continue;
      } else {
        printf("ERROR erasing %s\n", it->c_str());
      }
    }
    ++it;
  }
#endif



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
  // Called at qemu shutdown. Core hyde platform could log something here
  // HyDE program destructors will run independently from this at shutdown
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