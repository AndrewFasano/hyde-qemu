#ifndef HYDE_COMMON_H
#define HYDE_COMMON_H

#include <stdint.h>

//#define DEBUG
//#define WINDOWS

typedef struct {
  unsigned int callno;
  uint64_t args[6];
  unsigned int nargs;
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

typedef uint64_t ga; // Guest pointer - shouldnt't read directly

#endif