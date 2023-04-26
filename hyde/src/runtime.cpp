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
#include <mutex>

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

  // We universally ignore this to ensure signal handlers can be ended
  if (callno == SYS_rt_sigreturn) [[unlikely]] return;


#if 0
  if (callno == SYS_clone || callno == SYS_clone3 ||
      callno == SYS_fork || callno == SYS_vfork) ||
      callno == SYS_exit || callno == SYS_exit_group ||
      callno == SYS_execve || callno == SYS_execveat ||
  }
  #endif

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
    {
      std::lock_guard<std::mutex> lock(coopted_procs_lock_);
      coopted_procs_.insert(target);
    }
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

  // Inject the provided syscall. if it's a noreturn or a double
  // return we refuse to leave our values in the guest registers and must clean up now
  // Noreturn: We could keep it (noreturn might actually return on error), but it's gonna be a memleak in general
  // Double return: Child won't start at SC so it would start executing with bad R12-R15 and we can't cleanup
  // We can fix the double return case by hacking up the child start addr, but we don't need to
  if (!target->pImpl->inject_syscall(cpu, promise.value_)) {
    // Returns false if we can't track it (noreturn)
    // In that case we need to cleanup now - note coopter will never advance here
    // Kinda makes sense, if you yield exit, what would you expect?
    
    {
      std::lock_guard<std::mutex> lock(coopted_procs_lock_);
      coopted_procs_.erase(target);
    }
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

  // In the case of !done, we set orig_regs with R12-R15 modified
  // In the case of done, we set orig_regs with RAX clobbered to retval and RIP set to pc or custom return address

  if (!target->pImpl->is_coopter_done()) {
    // We have another syscall to run! Need to go back to pc-2 and ensure we only run at the right time
    //printf("Bring it back now y'all - %p needs rexec of %lx\n", target, pc-2);
    target->pImpl->at_sysret_redo_syscall(cpu, pc-2);
    return; // Updated registers
  }

  auto promise = target->pImpl->get_coopter_promise();
  ExitStatus result = promise.retval;

  // Hold onto name so we can cleanup with it
  std::string name = target->pImpl->get_name();
  //fprintf(fp, "SYSRET at %lx - all done, original sc (%lld) returns %lld, let's clean up target %p\n", pc, target->orig_regs.rax, new_regs.rax, target);

  // All done with injection. Restore original registers, free target
  {
    std::lock_guard<std::mutex> lock(coopted_procs_lock_);
    coopted_procs_.erase(target);
  }
  target->pImpl->demagic_and_deallocate(cpu, pc);

  // Based on result, update state for the whole hyde program
  switch (result) {
    case ExitStatus::FATAL:
      printf("[HyDE] Fatal error in %s\n", name.c_str());
      [[fallthrough]];
    case ExitStatus::FINISHED:
      // When a hyde program requests to quit, we immediately stop launching new coopters for it
      // but we need to wait until there are no actice coopters for it before we can safely disable hyde
      if (coopters_map_.count(name)) {
        // This capability is active - first time we've asked to unload it
        unload_hyde_prog(name);
        return; // Skip redundant call potentially_disable_hyde
      }
      break;

    case ExitStatus::SINGLE_FAILURE:
      printf("[HyDE] Warning %s experienced a non-fatal failure\n", name.c_str());
      break;

    case ExitStatus::SUCCESS:
      // Nothing to do
      break;
  }

  potentially_disable_hyde();
}

bool Runtime::load_hyde_prog(std::string path) {
  // introspection is enabled and program should be unique by the time we get here

  // Should we store this handle and dlcose it on unload?
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

  {
    std::lock_guard<std::mutex> lock(coopters_map_lock_);
    coopters_map_[path] = hooked_scs;
  }

  return true;
}

bool Runtime::unload_all(void) {
  // Called at qemu shutdown. Core hyde platform could log something here
  // HyDE program destructors will run independently from this at shutdown
  // Copy coopters_map_

  std::unordered_map<std::string, std::vector<int>> coopters_map_copy;
  {
    std::lock_guard<std::mutex> lock(coopters_map_lock_);
    coopters_map_copy = coopters_map_;
  }

  // Save to iterate through our copy while original is erased
  for (auto it = coopters_map_copy.begin(); it != coopters_map_copy.end(); ++it) {
    unload_hyde_prog(it->first);
  }

  return true;
}

bool Runtime::unload_hyde_prog(std::string path) {
  if (!coopters_map_.count(path)) {
    std::cerr << "HyDE program " << path << " has not been loaded" << std::endl;
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(pending_exits_lock_);
    // If this isn't already pending an unload, disable all the hooks it has in syscall_handlers_
    if (pending_exits_.count(path) == 0) {
      std::cerr << "HyDE program " << path << " now pending exit" << std::endl;
      pending_exits_.insert(path);

      for (auto it = coopters_map_[path].begin(); it != coopters_map_[path].end(); ++it) {
        syscall_handlers_.erase(*it);
      }

      // And erase it from our coopters_map entirely
      coopters_map_.erase(path);
    }
  }

  potentially_disable_hyde();
  return true;
}

  bool Runtime::potentially_disable_hyde(void) {
  // For each hyde program that's pending unload, check if any active
  // coopters are running it - if not, we can unload.
  // Finally, if nothing is loaded, disable hyde
  // Returns true if hyde is disabled, false otherwise
  
  std::lock_guard<std::mutex> lock(coopted_procs_lock_);
  std::lock_guard<std::mutex> lock2(pending_exits_lock_);

  for (auto it = pending_exits_.begin(); it != pending_exits_.end(); ) {
    // For each active coopter, check if it's managed by this hyde program
    bool active = false;
    for (const auto &kv : coopted_procs_) {
      if (kv->pImpl->get_name() == *it) {
        active = true;
        break;
      }
    }

    // No active coopter is based off this program - it's safe to unload!
    if (!active) {
        std::cout << "HyDE program " << *it << " no longer has active coopters. Disabling." << std::endl;
        it = pending_exits_.erase(it);
      } else {
        ++it; // XXX only increment if we didn't update with erase
      }
  }


  // If we're empty and nothing is pending, we can disable hyde
  if (coopters_map_.empty() && pending_exits_.empty()) {
    std::cerr << "HyDE Disabling all syscall introspection" << std::endl;
    // Disable syscall introspection
    disable_cpu_syscall_introspection();
    return true;
  }
  return false;
}

// Implement the custom deleter, necessary for some reason
void PluginDeleter::operator()(Plugin *plugin) const {
  delete plugin;
}