#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"
#include <syscall.h>

struct data {
  struct kvm_regs orig_regs;
  int refcount;
  bool parent_ret_pending;
  bool child_call_pending;
  bool force_retval;
  uint64_t retval;
};

FILE *fp = NULL;

Runtime::LoadedPlugin::~LoadedPlugin() = default;

#define R14_INJECTED_PARENT 0x5ca1ab1e

// On syscall stick a host ptr in r15
// On sysret use host ptr to cleanup and examine register delta

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
  data* target = nullptr;

  if (callno ==  SYS_rt_sigreturn) {
    // Special case and also noreturn
    return;
  }

  if (callno == SYS_clone || callno == SYS_clone3) {
    // Special case: child can't see altered R14/R15 so we must ignore these
    // XXX: We could actually handle these by storing the target function, changing it
    // to be the syscall insns, then doing something like how we handle fork where we
    // use a nop syscall on start then jump to the real function
    return;
  }

  if (callno == SYS_exit || callno == SYS_exit_group) {
    // noreturn
    return;
  }

  bool new_target = false;

  if (r14 == R14_INJECTED_PARENT) {
    target = (data*)r15;
    printf("SYSCALL AT %lx: Parent's forced syscall. child pid is %d, refcount is %d--\n", pc, callno, target->refcount);

    // Copy orig regs, nothing else
    data* new_target = new data();
    new_target->orig_regs = target->orig_regs;

    target->refcount--;
    if (target->refcount == 0) {
      printf("Parent hit second - freeing\n");
      delete target;
    }

    // Update our new target (will be placed in r15 later)
    // We want to run getpid, return callno (child PID), and then resume at pc which is just
    // after this syscall
    target = new_target;
    target->refcount = 1;
    target->parent_ret_pending = false;
    target->child_call_pending = false;

    // Force getpid, return callno, go to next insn (PC)
    target->orig_regs.rcx = pc; // Post-syscall insn
    target->orig_regs.rax = SYS_getpid; // We have PID as RAX right now, need to do noop
    target->force_retval = true;
    target->retval = callno; // Then, after return child pid

  // Need to do a no-op and then return child pid which we currently have in uh callno?

  } else if (r14 == R14_INJECTED) {
    target = (data*)r15;

    if (target->child_call_pending) {
      printf("SYSCALL at %lx: Child hits forced syscall with refcount %d--\n", pc, target->refcount);

      data* new_target = new data();
      new_target->orig_regs = target->orig_regs;

      target->refcount--;
      if (target->refcount == 0) {
        printf("Child hit second - freeing\n");
        delete target;
      }

      target = new_target;
      target->refcount = 1;
      target->parent_ret_pending = false;
      target->child_call_pending = false;

      // Force getpid, return 0, go to next insn (PC)
      target->orig_regs.rcx = pc; // Post-syscall insn
      target->orig_regs.rax = SYS_getpid;
      target->force_retval = true; // Needs to ret 0 in child
      target->retval = 0;


    } else {
      printf("Target is %p callno is %d, pc is %lx\n", target, callno, pc);
      pretty_print_regs(target->orig_regs);
      assert(0 && "What - child hits syscall but not child_call_pending?\n");
    }
  } else {
    // First time hitting a syscall, allocate our data and grab orig regs
    target = new data();
    target->parent_ret_pending = false;
    target->force_retval = false;
    target->refcount = 1;
    new_target = true;
  }

  kvm_regs new_regs = target->orig_regs;

  if (new_target) {
    // Grab original registers (post em_syscall)
    assert(get_regs(cpu, &target->orig_regs));
    new_regs = target->orig_regs;

    if (callno == SYS_fork || callno == SYS_vfork) {
      // Let's set RCX to pc so the child immediately executes the syscall instruction again.
      // We'll see a return in the parent and then a syscall in the child.
      // We'll need to check the magic R14/R15 values on subsequent syscalls to identify the child.
      // When we do, we need to run a NO-OP in the child, restore R14/R15 on return, and cleanup allocations when refcount hits 0

      target->refcount++; 
      new_regs.rcx = pc-2; // XXX shift backwards so both parent and child will hit the original syscall instruction. We'll special case both
      target->parent_ret_pending = true;
      target->child_call_pending = true;

    } else {
    }
  }


  assert(new_regs.r14 != R14_INJECTED && "Can't clobber our own magic value - shouldn't have gotten here");
 
  new_regs.r14 = R14_INJECTED;
  new_regs.r15 = (uint64_t)target;

  //printf("Running syscall %lld with target %p\n", target->orig_regs.rax, target);
  assert(set_regs(cpu, &new_regs));
}

void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {

  assert(r14 == R14_INJECTED && "VMM incorrectly triggered on_sysret");
  data* target = (data*)r15;

  //printf("Sysret with target %p. Original callno was %lld\n", target, target->orig_regs.rax);
  kvm_regs new_regs;
  assert(get_regs(cpu, &new_regs));


  if (target->parent_ret_pending) {
    // We're about re-execute the syscall instruction in the parent, need to be side effect free
    // Set R14 to special (second) magic value.
    // We'll change callno to getpid on the syscall and grab the PID then. We could alternatively do that here.

    // We leave R15 alone, we'll need it on the imminent syscall in the parent!
    new_regs.r14 = R14_INJECTED_PARENT;
    printf("SYSRET: first parent returns, going to re-exec no-op syscall (refcount %d: maintianing)\n", target->refcount);

  } else {
    new_regs.r14 = target->orig_regs.r14;
    new_regs.r15 = target->orig_regs.r15;
  }

  if (target->force_retval) {
    // Need retval to be 0 in child or child pid in parent
    new_regs.rax = target->retval;
    printf("\tSetting retval to %ld\n", target->retval);
  }

  fprintf(fp, "%p, syscall %lld, returns %lld\n", target, target->orig_regs.rax, new_regs.rax);

  if (!target->parent_ret_pending) {
    target->refcount--;
    if (target->refcount == 0) {
      delete target;
    }
  }

  assert(set_regs(cpu, &new_regs));
}

bool Runtime::load_hyde_prog(void* cpu, std::string path) {
  fp = fopen("/tmp/sc.txt","w");
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
  fclose(fp); // Uhh?
  delete plugin;
}