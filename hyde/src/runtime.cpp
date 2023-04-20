#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"

bool is_equal(kvm_regs r1, kvm_regs r2);

Runtime::LoadedPlugin::~LoadedPlugin() = default;

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
  // 1. Find and initialize the coopter
  // 2. Create a new syscall_context with find_and_init_coopter
  // 3. Handle the syscall using the created syscall_context and the handle_syscall method

  // Example:
  // auto ctx = find_and_init_coopter(cpu, cpu_id, fs, callno, asid, pc);
  // handle_syscall(ctx);
  // delete ctx;

  // Ignore sigreturn, track seccomp for this asid (and ignore if it's seccomp'd)
  //if (unlikely(!is_syscall_targetable(callno, asid))) {
  //  return;
  //}

  kvm_regs pre_inject;

  syscall_context *target_details = NULL;

  if (r14 == R14_INJECTED) [[unlikely]] {
    // On syscall: If previously-coopted, we'll have magic value in r14
    // and pointer to coopter state in r15
    target_details = (syscall_context*)r15;

    assert(0 && "This should never happen");

    if (target_details->pImpl->magic_ != 0x12345678) {
      printf("Magic mismatch - (UAF?) Last run syscall in this coopter was %d\n", target_details->pImpl->last_sc_);
      assert(target_details->pImpl->magic_ == 0x12345678);
    }
  } else {
    // Given the callno, check if it's in our map or if we have a catchall
    if (syscall_handlers_.find(-1) != syscall_handlers_.end()) {
      // We have a catchall, pretend callno is -1 so we use it
      callno = -1;
    }

    if (syscall_handlers_.find(callno) == syscall_handlers_.end()) {
      // No syscall handler for this
      return;
    }

    // Get & store original registers before we run the coopter's first iteration
    // XXX: Copy constructor here is important, don't just use directly
    auto creator = syscall_handlers_[callno];
    assert (&creator != &syscall_handlers_[callno]);

    // Look through coopters_map and find the key that has this callno
    std::string name;
    for (auto it = coopters_map_.begin(); it != coopters_map_.end(); it++) {
      // does this hyde program's coopted syscall vector contain callno?
      if (std::find(it->second.begin(), it->second.end(), callno) != it->second.end()) {
        name = it->first;
        break;
      }
    }

    target_details = new syscall_context(cpu);
    target_details->pImpl->set_coopter(creator);
    target_details->pImpl->set_name(name);
    target_details->pImpl->set_orig(rcx, r11); // Do we need these? Or do we just want to restore orig_regs.r11 -> rflags on restore


    coopted_procs_.insert(target_details);
    pre_inject = target_details->pImpl->get_orig_regs();

    //printf("Got arg R11 of %lx vs orig_regs R11 has %llx\n", r11, pre_inject.r11);
  }


  hsyscall sysc;
  auto promise = target_details->pImpl->get_coopter_promise();

  // New design policy - we should never coopt without a syscall to be yielded.
  // It's up to the hyde program / SDK to do skipping with SKIP_SYSNO, not us

  assert(!target_details->pImpl->is_coopter_done());

  // Get the syscall the coopter yielded
  sysc = promise.value_;
  //hyde_printf("Injecting syscall:");
  //dump_syscall(&sysc);

  // Now mark callno as "consumed" - we injected it, so if we hit here again before hitting sysret, we're in trouble
  assert(!sysc.consumed);
  sysc.consumed = true;

  target_details->pImpl->last_sc_ = sysc.callno;

  bool nomagic = true; // XXX DEBUG: never set magic

  // Set the syscall to the the guest CPU and update our tracking state
  if (!target_details->pImpl->set_syscall(cpu, sysc, nomagic)) {
    // we hit here for syscalls that we can't track:
    // sigreturn: Don't want to track, it's a special case and it doesn't return
    // execve, execveat, exit, exit_group: Can't track because they don't generally return - this is just to reduce memory pressure
    // clone, clone3: can't inject tracking because it will alter child process state (r14, r15 will be wrong at start)
    // In these cases we clean up here instead of on return

    // XXX hit this case for *everything* now!
    coopted_procs_.erase(target_details);
    delete target_details;

  } else {
    assert(0 && "Unreachable");
  }

#if 0
  } else if ( sysc.callno == __NR_fork || sysc.callno == __NR_vfork) {
    assert(0 && "XXX Disabled this just for debugging??");
    // fork and vfork *do* return, but they return twice - we can handle this on return
    // All these return 0 in parent, >0 in child, or <0 on error.
    // By fiat, we will only use the target_details object in the parent since we can't dup a coro
    //double_return_parents_.insert(target_details);
    double_return_children_.insert(target_details);
    //printf("On syscall: THISISIT set syscall to fork/vfork: %lu\n", sysc.callno);
  }
#endif

  kvm_regs post_inject;
  assert(get_regs(cpu, &post_inject));

  // We never add magic values, just the original call + args - these should
  // be identical to the original registers!
  if(!is_equal(pre_inject, post_inject)) {
    pretty_print_regs(pre_inject);
    pretty_print_regs(post_inject);
    assert(0 && "Registers changed after set_syscall");
  }
}

bool is_equal(struct kvm_regs r1, struct kvm_regs r2)
{
  return r1.rax == r2.rax &&
    r1.rbx == r2.rbx &&
    r1.rcx == r2.rcx &&
    r1.rdx == r2.rdx &&
    r1.rsi == r2.rsi &&
    r1.rdi == r2.rdi &&
    r1.rbp == r2.rbp &&
    r1.rsp == r2.rsp &&
    r1.r8 == r2.r8 &&
    r1.r9 == r2.r9 &&
    r1.r10 == r2.r10 &&
    r1.r11 == r2.r11 &&
    r1.r12 == r2.r12 &&
    r1.r13 == r2.r13 &&
    r1.r14 == r2.r14 &&
    r1.r15 == r2.r15 &&
    r1.rip == r2.rip &&
    r1.rflags == r2.rflags;
}


void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {
  // Should be impossible - VMM only triggers on sysret if we injected
  assert(r14 == R14_INJECTED && "VMM incorrectly triggered on_sysret");

  syscall_context *target_details = (syscall_context*)r15;

#if 0
  bool is_parent = retval != 0 && double_return_parents_.count(target_details);
  bool is_child = retval == 0 && double_return_children_.count(target_details);

  if (target_details->pImpl->last_sc_ == __NR_fork || target_details->pImpl->last_sc_ == __NR_vfork) {
    printf("Post fork (%lx) at %lx is_parent=%d, is_child=%d, retval is %d, in parents=%d, in children=%d\n", r15, pc, is_parent, is_child, retval,
    double_return_parents_.count(target_details)>0, double_return_children_.count(target_details)>0);
  }

  // If this return could've split into two processes, we need
  // to find the child and launch a new, user-specified coopter for it
  if (is_parent) {
    // If retval != 0, it's the parent (retval is child pid or negative error)
    double_return_parents_.erase(target_details);
    if ((long signed int)retval < 0) {
      // ...and the parent failed - don't wait for the child
      printf("\tParent: failed to fork\n");
      double_return_children_.erase(target_details);
    }else {
      printf("Parent forked OK\n");
    }
  }

  if (is_child) {
    // Child gets return value of 0
    double_return_children_.erase(target_details);

    // Need to launch new coopter for the child. Pulls from
    // target_details->pImpl->child_coopter_;

#if 0
    if (target_details->pImpl->has_child_coopter()) {
      printf("Launching child coopter from %lx\n", pc);
      target_details = new syscall_context(*target_details, cpu);
    } else
#endif
    {
      // Child un-coopted, just pretend we weren't here.
      // Get registers post-fork and restore r14, r15 from pre-fork
      struct kvm_regs child_regs;
      assert(get_regs(cpu, &child_regs));
      child_regs.rip = pc; // XXX: RIP is LSTAR, need PC which is insn after syscall
      child_regs.r14 = target_details->pImpl->get_orig_regs().r14;
      child_regs.r15 = target_details->pImpl->get_orig_regs().r15;
      assert(set_regs(cpu, &child_regs));

      return;
    }
  }
#endif

  if (target_details->pImpl->has_custom_retval()) [[unlikely]] {
    //hyde_printf("Did nop (really %lu) with rv=%lx.", details->orig_syscall->callno, retval);
    ;
  } else {
    target_details->pImpl->set_last_rv(retval);
    //hyde_printf("rv=%lx.", retval);
  }
  // If we set has_retval, it's in a funky state - we need to advance it so it will finish, otherwise we'll
  // keep yielding the last (no-op) syscall over and over again
  //details->coopter(); // Advance - will have access to the just returned value

  target_details->pImpl->advance_coopter();

  struct kvm_regs new_regs = target_details->pImpl->get_orig_regs();

  if (!target_details->pImpl->is_coopter_done()) {
    // We have more to do, re-execute the syscall instruction, which will hit on_syscall and then this fn again.
    //printf("Take it back\n");
    new_regs.rip = pc-2; // Take it back now, y'all
    new_regs.r14 = R14_INJECTED;
    new_regs.r15 = (uint64_t)target_details;

    assert(set_regs(cpu, &new_regs));
    return;
  }

  // All done - clean up time. Get result, examine to decide if we should disable this hyde program
  // or print a warning or just keep chugging along. At end of each coopter, we check if any hyde
  // programs can (now) be safely unloaded that previously wanted to unload.

  // If we're done, we have to restore rflags, r14, and r15. But we already have
  // those unclobbered values in new_regs from details->orig_regs!

  // Get result
  auto promise = target_details->pImpl->get_coopter_promise();
  ExitStatus result = promise.retval;

  // If a user specified a custom return value, we'll just take the resulting state after the
  // last injected syscall and update RAX to be that value.
  if (target_details->pImpl->has_custom_retval()) {
    new_regs.rax = target_details->pImpl->get_custom_retval();
  }
  // Otherwise, we'll keep the return value of the last injected syscall. Orig regs doesn't have
  // this value, so we need to get it first
  else {
    struct kvm_regs post_sc_regs;
    assert(get_regs(cpu, &post_sc_regs));
    new_regs.rax = post_sc_regs.rax;
  }

  // If we have a custom return, use it, otherwise set PC.
  // We *do* need to explicitly set this to pc, otherwise rip is the LSTAR value, not the next userspace insn!
  new_regs.rip = target_details->pImpl->has_custom_return() ? target_details->pImpl->get_custom_return() : pc;

  // Now update registers to get the correct PC and return value
  assert(set_regs(cpu, &new_regs));

  // Based on result, update state for the whole hyde program
  switch (result) {
    case ExitStatus::FATAL:
      printf("[HyDE] Fatal error in %s\n", target_details->pImpl->get_name().c_str());
      [[fallthrough]];
    case ExitStatus::FINISHED:
      printf("TODO: support unloading %s\n", target_details->pImpl->get_name().c_str());
      //if (!pending_exits.contains(name)) {
      //  printf("[HyDE] Unloading %s on cpu %d\n", name.c_str(), 0);
      //  //try_unload_coopter(target_details->name, cpu, 0); // XXX multicore guests, need to do for all CPUs?
      //  pending_exits.insert(name);
      //}
      break;

    case ExitStatus::SINGLE_FAILURE:
      printf("[HyDE] Warning %s experienced a non-fatal failure\n", target_details->pImpl->get_name().c_str());
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

  // Finally, we need to remove this coopter from the list of active coopters and free it
  target_details->pImpl->magic_ = -1;
  //delete target_details; // XXX DEBUG ONLY - Don't delete!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! XXX XXX
  coopted_procs_.erase(target_details);

}

bool Runtime::load_hyde_prog(void* cpu, std::string path) {
  void* handle = dlopen(path.c_str(), RTLD_LAZY);
  if (handle == NULL) {
    std::cerr << "Could not open capability at " << path << ": " << dlerror() << std::endl;
    return false;
  }

  // TODO WIP - get init_plugin function and call it
  auto init_plugin = reinterpret_cast<PluginInitFn>(dlsym(handle, "init_plugin"));
  if (init_plugin == nullptr) {
      std::cerr << "Failed to get init function: " << dlerror() << std::endl;
      dlclose(handle);
      return 1;
  }

  std::unordered_map<int, create_coopter_t> handlers;
  bool rv = init_plugin(handlers);

  // Plugin returned false (failure), don't register anything
  if (!rv) return false;

  // Update our internal map of handlers, ensuring no duplicates
  // also track hyde program name -> hooked_scs so we can unload later
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
  assert(0 && "NYI");
  return true;
}

bool Runtime::unload_hyde_prog(void* cpu, std::string path) {
  assert(0 && "NYI");
  return true;
}

// Implement the custom deleter
void PluginDeleter::operator()(Plugin *plugin) const {
  delete plugin;
}