#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"

struct data {
  struct kvm_regs orig_regs;
  int ctr;
};

Runtime::LoadedPlugin::~LoadedPlugin() = default;

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
  data* target = nullptr;

  //if (callno != SYS_listen) return; // Ignore anything but this
  if (callno > 10) return;

  if (r14 == R14_INJECTED) {
    // Just increment counter;
    target = (data*)r15;

  } else {
    // Store original data on the heap
    target = new data();

    target->ctr = 0;
    // Grab original registers (post em_syscall)
    assert(get_regs(cpu, &target->orig_regs));
    // and store original r14, r15 values in there. Wait that's dumb, they haven't changed
    //target->orig_regs.r14 = r14;
    //target->orig_regs.r15 = r15;
    
    // Calculate original rflags (undoing some of em_syscall)
    target->orig_regs.rflags = (target->orig_regs.r11 & 0x3c7fd7) | 2;

    target->orig_regs.rip = pc;

    // Less dumb: store original r11 and rcx values while we have them
    target->orig_regs.r11 = r11;
    target->orig_regs.rcx = rcx;

  }

  assert (target->ctr < 5);

  if (target->ctr == 0) {
    printf("Starting new coopter with target %p, original syscall %lld\n", target, target->orig_regs.rax);
    pretty_print_regs(target->orig_regs);
  } else if (target->ctr < 4) {
    printf("Continue to coopt target %p, ctr=%d\n", target, target->ctr);
  }else {
    printf("Run original syscall target %p, ctr=%d\n", target, target->ctr);
  }

  // Take original registers, set r14/r15 to magic + target pointer
  // and set rax to our new syscall
  kvm_regs new_regs = target->orig_regs;
  assert(new_regs.r14 != R14_INJECTED); // Sanity check - it's a copy

  new_regs.r14 = R14_INJECTED;
  new_regs.r15 = (uint64_t)target;

  if (target->ctr < 4) {
    // And change syscall to getpid
    new_regs.rax = __NR_getpid;
  } else {
    // Finally, run the original syscall
    // In other words, Leave RAX alone
    printf("\tLeaving RAX as %lld\n", target->orig_regs.rax);
  }

  assert(set_regs(cpu, &new_regs));
  target->ctr++;
}

void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {

  assert(r14 == R14_INJECTED && "VMM incorrectly triggered on_sysret");
  data* target = (data*)r15;

  printf("Return of %p with ctr %d\n", target, target->ctr);

  if (target->ctr < 4) {
    // We just returned from an injected syscall. We need to go back!
    kvm_regs new_regs = target->orig_regs;

    new_regs.rip = pc-2; // Make target go back to syscall instruction again

    // When we hit the syscall, we'll load the existing target
    new_regs.r14 = R14_INJECTED;
    new_regs.r15 = (uint64_t)target;

    // Change CPU to use our new registers
    assert(set_regs(cpu, &new_regs));

  } else {
    // All done coopting - restore r14/r15
    printf("Done with %p\n", target);
    kvm_regs new_regs;
    assert(get_regs(cpu, &new_regs));

    // How did registers change from before any SC to after our last injected SC?

    printf("Deleting coopter with target %p. Original SC rv is %lld\n", target, new_regs.rax);
    new_regs.r14 = target->orig_regs.r14;
    new_regs.r15 = target->orig_regs.r15;
    //new_regs.rip = pc; // These might be the same?
    assert(new_regs.rip == pc);
    //new_regs.rflags = target->orig_regs.rflags; // These should be the same?
    assert(new_regs.rflags == target->orig_regs.rflags); // These should be the same?

    printf("After full SC sequence delta is:\n");
    pretty_print_diff_regs(target->orig_regs, new_regs);
    // Expect: RAX was callno, now is retval

    delete target;
    assert(set_regs(cpu, &new_regs));
  }
}

bool Runtime::load_hyde_prog(void* cpu, std::string path) {
  return true;
}

bool Runtime::unload_all(void* cpu) {
  return true;
}

bool Runtime::unload_hyde_prog(void* cpu, std::string path) {
  return true;
}

// Implement the custom deleter
void PluginDeleter::operator()(Plugin *plugin) const {
  delete plugin;
}