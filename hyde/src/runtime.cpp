#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"
#include <syscall.h>
#include <cstring>

#define R14_INJECTED 0xdeadbeef
#define R14_INJECTED_PARENT 0x5ca1ab1e
#define JUNK_R14 0xcafebabe


FILE *fp = NULL;

struct Data {
  int magic;
  kvm_regs orig_regs;
  bool parent_ret_pending;
  bool child_call_pending;
  bool force_retval;
  uint64_t retval;
  int pending;
  uint64_t pending_pc;
  int ctr;

  // Initialize and orig_regs based on CPU
  Data(void* cpu) : magic(0x12345678), orig_regs(), parent_ret_pending(false), child_call_pending(false), force_retval(false), pending(-1), pending_pc(0), ctr(0), refcount(1) {
      assert(get_regs(cpu, &orig_regs));
  }

  // Create a new instance with the same orig_regs as the old
  Data(const Data& other) : magic(0x12345678), parent_ret_pending(false), child_call_pending(false), force_retval(false), retval(0), pending(-1), pending_pc(0), ctr(0), refcount(1) {
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
        fprintf(fp, "Freeing %p\n", this);
        delete this;
    }
  }

  bool is_fork(int callno) const {
    return callno == SYS_fork || callno == SYS_vfork;
  }

  void handle_fork(kvm_regs& new_regs, uint64_t pc) {
    new_regs.rcx = pc - 2;
    addRef();
    parent_ret_pending = true;
    child_call_pending = true;
  }

  void update_regs_for_injected_syscall(kvm_regs& new_regs, uint64_t new_callno, uint64_t pc) {
    new_regs.rax = new_callno;
    new_regs.rcx = pc - 2;
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

  void prepare_to_run(void* cpu, kvm_regs& new_regs) {
    // Set magic r14/r15, store callno in pending, bump ctr, and set regs
    new_regs.r14 = R14_INJECTED;
    new_regs.r15 = reinterpret_cast<uint64_t>(this);
    pending = (int)new_regs.rax; // Callno, won't overflow an int
    pending_pc = new_regs.rcx;
    ctr++;
    assert(set_regs(cpu, &new_regs));
  }

private:
  int refcount;
};


Runtime::LoadedPlugin::~LoadedPlugin() = default;

// On syscall stick a host ptr in r15
// On sysret use host ptr to cleanup and examine register delta

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15, uint64_t cpu_id) {
  Data* target = nullptr;

  if (callno ==  SYS_rt_sigreturn) {
    // Sigreturn will pop kernel-saved registers at the end of a signal handler.
    // The kernel-saved regs should include our magic value if the signal was raised while in a tracked syscall
    // When this event happens, we can't reliably lookup our data struct, but if we had one it will reliably be
    // restored - so do nothing here.

    // Sanity check - are we restoring to something after we saw a pending? That would be cool
    // XXX By the time the signal handlers calls sigreturn I think it could've easily changed r14/r15
#if 0
  // Huh, this happens a lot
  if (r14 == R14_INJECTED) {
      target = (Data*)r15;
      if (target->pending != -1) {
        printf("Sigreturn going back to previously-pending syscall %d\n", target->pending);
      }
    }
#endif
    return;
  }

  if (callno == SYS_clone || callno == SYS_clone3) {
    // Special case: child can't see altered R14/R15 so we must ignore these
    // We could probably use the same approach as we do fork here if we wanted to track.
    return;
  }

  if (callno == SYS_exit || callno == SYS_exit_group || callno == SYS_execve || callno == SYS_execveat) {
    // noreturn: don't try tracking these since cleaning up heap allocated data would be hard
    return;
  }

#if 1
  if (callno == SYS_fork || callno == SYS_vfork) {
    // Testing - can we just ignore?
    return;
  }
#endif


  if (r14 == R14_INJECTED_PARENT) {
    target = (Data*)r15;
    assert(target->magic == 0x12345678);
    //fprintf(fp, "Syscall %d with injected parent: %p\n", callno, target);

    //printf("SYSCALL aT %lx: Parent's forced syscall. child pid is %d, refcount is %d--\n", pc, callno, target->refcount);

    // Create a copy of target to use
    Data* new_target = new Data(*target);
    target->release();

    // Update our new target (will be placed in r15 later)
    // We want to run getpid, return callno (child PID), and then resume at pc which is just
    // after this syscall
    target = new_target;
    fprintf(fp, "Created new target for parent %p\n", target);

    // Force getpid, return child pc (callno), then continue
    target->update_regs_for_nop(pc, (uint64_t)callno);

  } else if (r14 == R14_INJECTED) {
    // We injected a syscall, it returned, and now we're injecting again
    // For this minimal example, this means we ran getpid and now we're onto
    // the original syscall
    target = (Data*)r15;
    assert(target->magic == 0x12345678);
    //fprintf(fp, "Syscall %d after injection: %p\n", callno, target);

    if (target->pending != -1) {
      // Psych, we're actually in a signal handler!
      // Change r14 to junk so we ignore this. On sigreturn target will get our magic r14/r15 again

      fprintf(fp, "Detected signal handler at %lx callno %d with pending %d changing R14 target is %p\n", pc, callno, target->pending, target);
      kvm_regs regs;
      assert(get_regs(cpu, &regs));
      regs.r14 = JUNK_R14;
      regs.r15 = 0;
      assert(set_regs(cpu, &regs));
      return;
    }

    if (target->child_call_pending) {
      // Child is now running and it hits our forced syscall, start
      // with a no-op then return 0
      Data* new_target = new Data(*target);
      target->release();
      target = new_target;
      fprintf(fp, "Created target %p for child\n", target);

      // Force getpid, return 0, go to next insn (PC)
      target->update_regs_for_nop(pc, 0);
    }

    assert(target->ctr < 2); // Ctr is 0 for our inject, then 1 for original

  } else {
    // First time hitting a syscall, allocate our Data and grab orig regs
    target = new Data(cpu);
    fprintf(fp, "Created new target %p\n", target);
    //fprintf(fp, "Syscall %d just created: %p\n", callno, target);
  }

  kvm_regs new_regs = target->orig_regs;


  if (target->ctr == 0) {
    // First time, inject getpid
    target->update_regs_for_injected_syscall(new_regs, SYS_getpid, pc);

  } else if (target->ctr > 0) {
    // Second time - run original syscall. Or if it's a fork, handle it
    // Update PC to next insn
    fprintf(fp, "Syscall running original %lld with target %p\n", new_regs.rax, target);
    target->update_regs_for_original_syscall(new_regs, pc);

    if (target->is_fork(callno)) {
      target->handle_fork(new_regs, pc);
    }
  }

  target->prepare_to_run(cpu, new_regs);
  fprintf(fp, "CALL #%d cpu %ld, target %p set callno to %lld, pending=%d, pending_pc=%lx\n", target->ctr, cpu_id, target, new_regs.rax, target->pending, target->pending_pc);
}

void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15, uint64_t cpu_id) {

  assert(r14 == R14_INJECTED && "VMM incorrectly triggered on_sysret");

  Data* target = (Data*)r15;
  assert(target->magic == 0x12345678);

  fprintf(fp, "RET #%d cpu %ld target %p pending=%d pending_pc=%lx, retval=%d pc=%lx\n", target->ctr, cpu_id, target, target->pending, target->pending_pc, retval, pc);

  //assert(target->pending != -1);
#if 0
// Edge case with signal handling again? sysret runs twice without syscall
  i (target->pending == -1) {
    printf("Pending was -1 for target %p, pc=%lx\n", target, pc);
    fflush(NULL);
    assert(0);
  }
#endif
  if (target->pending == -1) {
    // Need to undo what we did on previous sysret since hti sis a dup
    target->addRef();
  }

  if (pc != target->pending_pc) {
    fprintf(fp, "sysret of %p expected at %lx but was at %lx\n", target, target->pending_pc, pc);
    fflush(NULL);
    assert(0);
  }

  target->pending = -1; // TODO: how to handle with parent/childs?

  //fprintf(fp, "Sysret with target %p. Original callno was %lld\n", target, target->orig_regs.rax);

  if (target->ctr > 1) {
    // All done with injection. Restore original registers, unless it's a fork parent
    kvm_regs new_regs;
    assert(get_regs(cpu, &new_regs));

    //bool force_retval = target->force_retval;
    uint64_t retval = (target->force_retval) ? target->retval : new_regs.rax;

    if (target->parent_ret_pending) {
      // We're about re-execute the syscall instruction in the parent, need to be side effect free
      // Set R14 to special (second) magic value.
      // We'll change callno to getpid on the syscall and grab the PID then. We could alternatively do that here.

      // We leave R15 alone, we'll need it on the imminent syscall in the parent!
      new_regs.r14 = R14_INJECTED_PARENT;
      //printf("SYSRET: first parent returns, going to re-exec no-op syscall (refcount %d: maintianing)\n", target->refcount);

    } else {
      // Restore original R14/R15 values and decrement refcount
      new_regs.r14 = target->orig_regs.r14;
      new_regs.r15 = target->orig_regs.r15;

      target->release();
    }

    //if (force_retval) {
    //  new_regs.rax = retval;
    //}
    new_regs.rax = retval;

    assert(set_regs(cpu, &new_regs));

  }
  // Else We have another syscall to inject. Fortunately we've set ourselves up to return to
  // the syscall instruction so we don't have to do anything here

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