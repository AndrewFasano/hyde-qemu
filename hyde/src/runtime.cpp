#include <stdio.h>
#include <assert.h>
#include "hyde/include/plugin_common.h"
#include "hyde/include/runtime.h"

Runtime::LoadedPlugin::~LoadedPlugin() = default; // Add this line


// Implement load_plugin, unload_plugin, and handle_syscall
// ...

syscall_context* Runtime::find_and_init_coopter(void* cpu, unsigned long cpu_id, unsigned long fs, int callno, unsigned long asid, unsigned long pc) {
  // 1. Find the coopter (not provided in the example)
  // 2. Initialize the coopter
  // 3. Create a new syscall_context and initialize it with the relevant information
  // 4. Return the syscall_context

  // Example:
  // auto ctx = std::make_unique<syscall_context>();
  // ctx->pImpl->initialize(cpu, cpu_id, fs, callno, asid, pc);
  // return ctx.release();
  return nullptr;
}

void Runtime::on_syscall(void* cpu, uint64_t pc, int callno, uint64_t rcx, uint64_t r11, uint64_t r14, uint64_t r15) {
  // 1. Find and initialize the coopter
  // 2. Create a new syscall_context with find_and_init_coopter
  // 3. Handle the syscall using the created syscall_context and the handle_syscall method

  // Example:
  // auto ctx = find_and_init_coopter(cpu, cpu_id, fs, callno, asid, pc);
  // handle_syscall(ctx);
  // delete ctx;

  printf("Syscall\n");
}

void Runtime::on_sysret(void* cpu, uint64_t pc, int retval, uint64_t r14, uint64_t r15) {
  // Handle the syscall return event (implementation not provided in the example)
  printf("Sysret\n");
}

bool Runtime::load_hyde_prog(void* cpu, std::string path) {
  void* handle = dlopen(path.c_str(), RTLD_LAZY);
  if (handle == NULL) {
    std::cerr << "Could not open capability at " << path << ": " << dlerror() << std::endl;
    return false;
  }

std::cerr << "TODO: Implement load_hyde_prog: " << path << std::endl;

#if 0
  coopter_f* do_coopt;
  do_coopt = (coopter_f*)dlsym(handle, "should_coopt");
  if (do_coopt == NULL) {
    std::cerr << "Could not find should_coopt function in capability: " << dlerror() << std::endl;
    dlclose(handle);
    return false;
  }

  coopters[path] = *do_coopt;
#endif
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