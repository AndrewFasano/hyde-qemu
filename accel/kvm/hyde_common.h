#ifndef HYDE_COMMON_H
#define HYDE_COMMON_H

#include <stdint.h>
#include <tuple>

//#define DEBUG
//#define WINDOWS

typedef struct {
  uint64_t callno;
  unsigned int nargs;
  uint64_t args[6];
  //std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t> args;

  uint64_t retval; // Only used when co-opting
  bool has_retval;
} hsyscall;

typedef char ga; // Guest pointer - always use as `ga*` or you'll get truncation issues

#endif