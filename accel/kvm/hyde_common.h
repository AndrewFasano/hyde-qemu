#ifndef HYDE_COMMON_H
#define HYDE_COMMON_H
#include <stdint.h>

typedef struct {
  unsigned int callno;
  unsigned long args[6];
  unsigned int nargs;
  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

#endif