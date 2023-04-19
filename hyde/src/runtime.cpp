#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"


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

  syscall_context *target_details = NULL;
  bool first = false;

  if (r14 == R14_INJECTED) [[unlikely]] {
    // On syscall: If previously-coopted, we'll have magic value in r14
    // and pointer to coopter state in r15
    target_details = (syscall_context*)r15;
  } else {

    auto it = syscall_handlers_.find(callno);
    create_coopter_t creator;
    if ((it != syscall_handlers_.end())) {
      // First choice: a syscall-specific handler
      creator = it->second;
    } else if (catch_all_handler_ != nullptr) {
      // Second choice: a catch-all handler
      creator = catch_all_handler_;
    } else {
      // No handler for this syscall
      return;
    }

    first = true;
    target_details = new syscall_context(cpu);

    coopted_procs_.insert(target_details);

    target_details->pImpl->set_coopter(creator);
  }

  hsyscall sysc;
  auto promise = target_details->pImpl->get_coopter_promise();

   if (!target_details->pImpl->is_coopter_done()) [[likely]] {
    // We have something to inject, it's stored in the promise value
    sysc = promise.value_;

    //hyde_printf("Injecting syscall:");
    //dump_syscall(&sysc);
    //hyde_printf("have syscall to inject: replace %lu with %lu\n", target_details->orig_syscall->callno, sysc.callno);

  } else if (!first) {
    // We shouldn't get here - the coopter is done, but we missed
    // this on the last sysret we advanced it in? Impossible!
    assert(0 && "FATAL: Injecting syscall, but from a previously-created co-routine that is done\n");
  } else {
    // Nothing to inject and this is the first syscall
    // so we need to run a skip! We do this with a "no-op" syscall
    // and hiding the result on return

    if (!target_details->pImpl->has_custom_retval()) {
      // No-op: user registered a co-opter but it did nothing so we're already done
      // The user didn't run the original syscall, nor did they set a return value.
      // This means the guest is going to see the original callno as a result.
      // This is probably a user error - warn about it.
      //printf("USER ERROR in %s: co-opter ran 0 syscalls (not even original) and left result unspecified.\n", target_details->name.c_str());
      printf("USER ERROR co-opter ran 0 syscalls (not even original) and left result unspecified.\n");
      //target_details->coopter.destroy();

      // Remove target_details from oru coopted_procs set
      coopted_procs_.erase(target_details);
      //delete target_details->orig_syscall;
      delete target_details;
      return;
    }

    // We have a return value specified - run the skip syscall
    // and on return, set the return value to the one specified
    // XXX NYI really
    sysc = hsyscall(SKIP_SYSNO);
    sysc.set_retval(target_details->pImpl->get_custom_retval());

    //hyde_printf("skip original (%ld) replace with %ld and set RV to %lx\n", target_details->orig_syscall->callno, sysc.callno, target_details->orig_syscall->retval);
  }



  if (!target_details->pImpl->set_syscall(cpu, sysc)) {
    // It's a noreturn syscall, we can't catch it later so clean up now
    coopted_procs_.erase(target_details);
    delete target_details;
  }
  else if (sysc.callno == __NR_clone || sysc.callno == __NR_fork || \
           sysc.callno == __NR_vfork) {
    // Special handling for syscalls that return twice (in two processes)
    // All these return 0 in parent, >0 in child, or <0 on error

    double_return_parents_.insert(target_details);
    double_return_children_.insert(target_details);
  }
}

void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {
  // Should be impossible - VMM only triggers on sysret if we injected
  assert(r14 == R14_INJECTED && "VMM incorrectly triggered on_sysret");

  syscall_context *target_details = (syscall_context*)r15;

  bool has_parent = double_return_parents_.count(target_details);
  bool has_child = double_return_children_.count(target_details);

  // If this return could've split into two processes, we need
  // to find the child and launch a new, user-specified coopter for it
  if (has_parent) {
    // This syscall result could have a parent
    if (retval != 0) {
      // If retval != 0, it's the parent (retval is child pid or negative error)
      double_return_parents_.erase(target_details);
      if ((long signed int)retval < 0) {
        // ...and the parent failed - don't wait for the child
        double_return_children_.erase(target_details);
      }else {
        printf("In parent at %lx\n", pc);
      }
    }
  }
  if (has_child && retval == 0) {
    // Child gets return value of 0
    double_return_children_.erase(target_details);

    // Need to launch new coopter for the child. Pulls from
    // target_details->pImpl->child_coopter_;

    if (target_details->pImpl->has_child_coopter()) {
      printf("Launching child coopter from %lx\n", pc);
      target_details = new syscall_context(*target_details, cpu);
    } else {
      printf("Restoring child to un-coopted at %lx\n", pc);
      // No child coopter specified. We need to restore arguments
      // that we clobbered, but other than that we just move on?

      // Get registers now. RAX has fork retval (0)
      // Restore r14, r15 from original and then bail
    struct kvm_regs regs_on_ret2;
      assert(get_regs(cpu, &regs_on_ret2));

      regs_on_ret2.r14 = target_details->pImpl->get_orig_regs().r14;
      regs_on_ret2.r15 = target_details->pImpl->get_orig_regs().r15;

      if (regs_on_ret2.r14 == R14_INJECTED) {
        // This child inherited parent registers, so we need to unclobber
        //  R14/R15
        assert(set_regs(cpu, &regs_on_ret2));
      }
      return;
    }
  }

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

  if (target_details->pImpl->has_custom_retval()) {
    // A user set a retval in orig_syscall object, return that
    // This is how we'd do INJECT_SC_A, ORIG_SC, INJECT_SC_B and
    // pretend nothing was injected
    new_regs.rax = target_details->pImpl->get_custom_retval();
    printf("change return to be %llx\n", new_regs.rax);
  } else {
    // We weren't told the orig_syscall has a retval, that means the last
    // return value should be what we pass back. This is how we'd do
    // INJECT_SC_A, INJECT_SC_B, ORIG.
    struct kvm_regs regs_on_ret2;
    assert(get_regs(cpu, &regs_on_ret2));
    new_regs.rax = regs_on_ret2.rax;

    // In this case do we actually need to do an extra setregs at all?
  }

  // If we have a custom return, use it, otherwise set PC.
  // XXX we *do* need to explicitly set this to pc, otherwise rip is
  // the LSTAR value, not the next userspace insn.
  // I assume this is because of a delay with KVM updating
  // registers, not because there's more to do in the LSTAR kernel code?
  new_regs.rip = target_details->pImpl->has_custom_return() ? target_details->pImpl->get_custom_return() : pc;

  // Remove this active coopter
  std::string name = "TODO"; //details->name;
  delete target_details;

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

  assert(set_regs(cpu, &new_regs));
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

  // Init plugin with our map (it can update directly). Returns false on err
  create_coopter_t new_catchall = nullptr;
  bool rv = init_plugin(syscall_handlers_, new_catchall);

  if (rv && new_catchall != nullptr) {
    if (catch_all_handler_ != nullptr) {
      std::cerr << "ERROR: Multiple catchall coopters not supported" << std::endl;
      return false;
    }
    catch_all_handler_ = new_catchall;
  }

  return rv;
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