#include <stdio.h>
#include <assert.h>
#include "plugin_common.h"
#include "syscall_coroutine.h"
#include "runtime.h"
#include "syscall_context_internal.h"
#include "qemu_api.h"

struct data {
  struct kvm_regs orig_regs;
};

Runtime::LoadedPlugin::~LoadedPlugin() = default;


// On syscall stick a host ptr in r15
// On sysret use host ptr to cleanup and examine register delta

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
  data* target = nullptr;

  //if (callno != SYS_listen) return; // Ignore anything but this
  if (callno > 10) return;

  // Store original data on the heap
  target = new data();

  // Grab original registers (post em_syscall)
  assert(get_regs(cpu, &target->orig_regs));
  
  // Undo some of em_sysret for our orig_regs values?
  //printf("\tWe could change orig_regs.rflags from %llx to %lx\n", target->orig_regs.rflags, (r11 & 0x3c7fd7) | 2);
  //target->orig_regs.rflags = (r11 & 0x3c7fd7) | 2;

  //printf("\tWe could change orig_regs.rip from %llx to %lx\n", target->orig_regs.rip, pc);
  //target->orig_regs.rip = pc; // XXX kills the guest

  // Less dumb: store original r11 and rcx values while we have them
  //target->orig_regs.r11 = r11;
  //target->orig_regs.rcx = rcx;

  kvm_regs new_regs = target->orig_regs;

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

  new_regs.r14 = target->orig_regs.r14;
  new_regs.r15 = target->orig_regs.r15;
  // Sanity checks:
  //assert(new_regs.rip == pc);
  //assert(new_regs.rflags == target->orig_regs.rflags);

  //printf("After full SC sequence delta is:\n");
  //pretty_print_diff_regs(target->orig_regs, new_regs);
  printf("Syscall %lld returned %lld\n", target->orig_regs.rax, new_regs.rax);

  delete target;
  assert(set_regs(cpu, &new_regs));
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