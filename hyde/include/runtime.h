#pragma once

//#include "plugin_common.h"
//#include "syscall_context.h"
#include <iostream>
#include "syscall_coroutine.h"
#include <unordered_map>
#include <vector>
#include <memory>
#include <string>
#include <map> // can drop later
#include <dlfcn.h>
//#include "kvm_vcpu_ioctl_wrapper.h"

class Plugin;
class syscall_context;
struct PluginDeleter;
// Necessary to use unique_ptr with Plugin
using PluginPtr = std::unique_ptr<Plugin, PluginDeleter>;

#if 0
int getregs(syscall_context*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(syscall_context*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);
#endif

//bool translate_gva(syscall_context *r, uint64_t gva, uint64_t* hva); // Used in common
bool can_translate_gva(void*cpu, uint64_t gva);
void set_regs_to_syscall(syscall_context* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig);

#define IS_NORETURN_SC(x)(x == __NR_execve || \
                          x == __NR_execveat || \
                          x == __NR_exit || \
                          x == __NR_exit_group || \
                          x == __NR_rt_sigreturn)

//#define PRINT_REG(REG) std::cout << "  " << #REG << ": " << std::hex << std::setw(16) << std::setfill('0') << regs.REG << std::endl;

#ifdef WINDOWS
#define SKIP_SYSNO 0x01c0 // NtTestAlert - Probably need a better one
#else
#define SKIP_SYSNO __NR_getpid
#endif


class Runtime {
public:
  void load_plugin(const std::string& plugin_path);
  void unload_plugin(const std::string& plugin_path);

  bool load_hyde_prog(void* cpu, std::string path);
  bool unload_hyde_prog(void* cpu, std::string path);
  bool unload_all(void* cpu);

  void on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15);
  void  on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15);

private:
  syscall_context* find_and_init_coopter(void* cpu, unsigned long cpu_id, unsigned long fs, int callno, unsigned long asid, unsigned long pc);
  bool is_syscall_targetable(int callno, unsigned long asid);

  using PluginPtr = std::unique_ptr<Plugin>;
  using CreatePluginFunc = Plugin* (*)();

  struct LoadedPlugin {
    ~LoadedPlugin(); // Add this line

    PluginPtr plugin;
    void* handle;
  };

  void register_plugin_handlers(Plugin* plugin);

  // TODO: delete this one
  //std::map<std::string, coopter_f*> coopters; // filename -> should_coopt function

  std::unordered_map<std::string, LoadedPlugin> loaded_plugins_;
  //std::unordered_map<int, SyscallHandler> syscall_handlers_;
  //std::vector<SyscallHandler> all_syscalls_handlers_;
};

// Define the custom deleter
struct PluginDeleter {
  void operator()(Plugin *plugin) const;
};
