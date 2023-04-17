kvm_ss = ss.source_set()
kvm_ss.add(files(
  'include/plugin_common.h',
  'include/syscall_context.h',
  'include/runtime.h',
  'src/syscall_context.cpp',
  'src/syscall_context_internal.cpp',
  'src/syscall_context_internal.h',
  'src/runtime.cpp',
  'src/runtime_instance.cpp',
  'src/qemu_api.cpp',
))

# Setup cflags - doesn't work
#hyde_inc = '-I' + meson.current_source_dir() + '/include'
#hyde_c_args = [hyde_inc, '-std=c++20', '-fcoroutines-ts']
#include_dirs += meson.current_source_dir() + '/include'

# Raise error for GCC since it won't work with our coroutines
if cc.get_id() == 'gcc'
  error('GCC is not supported. Please use Clang.')
endif

specific_ss.add_all(when: 'CONFIG_KVM', if_true: kvm_ss)