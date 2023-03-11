#ifndef HYDE_COMMON_H
#define HYDE_COMMON_H

#include <stdint.h>

//#define DEBUG
//#define WINDOWS

typedef struct {
  uint64_t callno;
  unsigned int nargs;
  uint64_t args[6];
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

typedef uint64_t ga; // Guest pointer - shouldnt't read directly

#endif