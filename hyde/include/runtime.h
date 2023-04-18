#pragma once

#include "syscall_coroutine.h"

#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#define R14_INJECTED 0xdeadbeef

#if 0
int getregs(syscall_context*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(syscall_context*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);
void set_regs_to_syscall(syscall_context* details, void *cpu, hsyscall *sysc, struct kvm_regs *orig);
#define PRINT_REG(REG) std::cout << "  " << #REG << ": " << std::hex << std::setw(16) << std::setfill('0') << regs.REG << std::endl;
#endif

#define SKIP_SYSNO __NR_getpid


class Plugin;
class syscall_context;
struct PluginDeleter;
// Necessary to use unique_ptr with Plugin
using PluginPtr = std::unique_ptr<Plugin, PluginDeleter>;

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
    ~LoadedPlugin();
    PluginPtr plugin;
    void* handle;
  };

  void register_plugin_handlers(Plugin* plugin);

  // TODO: delete this one
  //std::map<std::string, coopter_f*> coopters; // filename -> should_coopt function

  std::unordered_map<std::string, LoadedPlugin> loaded_plugins_;
  std::unordered_map<int, create_coopter_t> syscall_handlers_;
  std::set<syscall_context*> coopted_procs_ = {}; // Procs that have been coopted

  std::set<syscall_context*> double_return_parents_ = {};
  std::set<syscall_context*> double_return_children_ = {};

  //std::vector<SyscallHandler> all_syscalls_handlers_;

  using PluginInitFn = bool (*)(std::unordered_map<int, create_coopter_t>&);

};

// Custom deleter. This is necessary to use unique_ptr with Plugin
// since it's forward declared to avoid a circular dependency. Ugh C++
struct PluginDeleter {
  void operator()(Plugin *plugin) const;
};
