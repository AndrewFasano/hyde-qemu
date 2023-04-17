#include "hyde/include/runtime.h"
// Singleton pattern

Runtime& get_runtime_instance() {
  static Runtime runtime_instance;
  return runtime_instance;
}
