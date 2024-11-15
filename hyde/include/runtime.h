#pragma once

#include "syscall_coroutine.h"

#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#define R14_INJECTED 0xdeadbeef
#define SKIP_SYSNO __NR_getpid

class Plugin;
class SyscallCtx;
struct PluginDeleter;
// Necessary to use unique_ptr with Plugin
using PluginPtr = std::unique_ptr<Plugin, PluginDeleter>;

class Runtime {
public:
  bool load_hyde_prog(std::string path);

  /* Unload a specific program. Calls potentially_disable_hyde at end */
  bool unload_hyde_prog(std::string path);

  /* If no syscalls are set to be coopted and no coopters are running, disable */
  bool potentially_disable_hyde(void);

  bool unload_all(void);

  void on_syscall(void* cpu, uint64_t pc, uint64_t callno, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15);
  void on_sysret( void* cpu, uint64_t pc, uint64_t retval, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15);

private:
  //SyscallCtx* find_and_init_coopter(void* cpu, unsigned long cpu_id, unsigned long fs, int callno, unsigned long asid, unsigned long pc);
  //bool is_syscall_targetable(int callno, unsigned long asid);

  using PluginPtr = std::unique_ptr<Plugin>;
  using CreatePluginFunc = Plugin* (*)();

  struct LoadedPlugin {
    ~LoadedPlugin();
    PluginPtr plugin;
    void* handle;
  };

  SyscallCtx* get_reinject_ctx(void* cpu, uint64_t pc, uint64_t rax, uint64_t r12, uint64_t r13, uint64_t r14, uint64_t r15);

  // A coopter/coroutine has finished with its injection, should we report a warning or unload the program because it's done?
  void on_coopter_finish(SyscallCtx* target, ExitStatus result);


  void register_plugin_handlers(Plugin* plugin);

  // Plugins populate these in their init methods
  std::unordered_map<int, create_coopter_t> syscall_handlers_;

  std::unordered_map<std::string, std::vector<int>> coopters_map_; // filename -> hooked syscalls
  std::mutex coopters_map_lock_;

  std::unordered_map<std::string, LoadedPlugin> loaded_plugins_;
  std::set<SyscallCtx*> coopted_procs_ = {}; // Procs that have been coopted
  std::mutex coopted_procs_lock_;

  std::set<std::string> pending_exits_ = {}; // Procs that have been coopted
  std::mutex pending_exits_lock_;

  using PluginInitFn = bool (*)(std::unordered_map<int, create_coopter_t>&);
};

// Custom deleter. This is necessary to use unique_ptr with Plugin
// since it's forward declared to avoid a circular dependency. Ugh C++
struct PluginDeleter {
  void operator()(Plugin *plugin) const;
};
