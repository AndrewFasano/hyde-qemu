#ifndef HYDE_H
#define HYDE_H


#include <exception>
#include <linux/kvm.h>
#include <cassert>


//#define DEBUG
//#define WINDOWS
#include "hyde_macros.h"
#include "hyde_common.h"

#include "hyde_coro.h"

#define on_ret_t void(_asid_details*, void*, unsigned long, unsigned long, unsigned long)
 
typedef uint64_t ga; // Guest pointer - shouldnt't read directly
typedef struct _asid_details {
  coopter_t coopter;
  struct kvm_regs orig_regs;
  hsyscall *orig_syscall;
  void* cpu;
  long unsigned int retval;
#ifdef DEBUG
  unsigned int injected_callno; // Debug only
#endif
  unsigned int asid;
  unsigned long int orig_rcx;
  unsigned long int orig_r11;
  bool use_orig_regs; // If set, after sysret we'll restore RCX/R11 to their pre-syscall values
  unsigned long custom_return;
  bool modify_original_args;
  std::function<void(struct kvm_regs*)> *modify_on_ret;

  std::function<on_ret_t> *on_ret;
  hsyscall scratch;
} asid_details;

// TODO: these should be another class, want to be able to return status
SyscCoroutine ga_memcpy(asid_details* r, void* out, ga* gva, size_t size);
//SyscCoroutine ga_memmove(asid_details* r, ga* dest, void* src, size_t size);
SyscCoroutine ga_map(asid_details* r,  ga* gva, void** host, size_t min_size);


void dump_syscall(hsyscall h) {
#ifdef DEBUG
  printf("syscall_%d(", h.callno);
  for (size_t i=0; i < h.nargs; i++) {
    printf("%#lx", h.args[i]);
    if ((i+1) < h.nargs) printf(", ");
  }
  printf(")\n");
#endif
}

//void default_on_ret(asid_details* a, void* cpu, unsigned long, unsigned long, unsigned long);
//void skip_on_ret(asid_details* a, void* cpu, unsigned long pc, unsigned long asid, unsigned long retval);

__u64 memread(asid_details*, __u64, hsyscall*);
__u64 translate(void *cpu, __u64 gva, int* status);
int getregs(asid_details*, struct kvm_regs *);
int getregs(void*, struct kvm_regs *);
int setregs(asid_details*, struct kvm_regs *);
int setregs(void*, struct kvm_regs *);
void build_syscall(hsyscall*, unsigned int callno);
void build_syscall(hsyscall*, unsigned int, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);
void build_syscall(hsyscall*, unsigned int, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long, int unsigned long);

// macros for memory read and syscall yielding
#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)
#define __scratchvar(x) TOKENPASTE2(x, __LINE__ )


#ifdef DEBUG
#define __memread_status(out, r, ptr, success) do { \
    *success = false; \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      printf("Failed to read %lx - inject a syscall\n", (unsigned long)ptr); \
      co_yield __scratchvar(sc); \
      printf("SC returns 0x%lx\n", r->retval); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out != (__u64)-1) { \
        *success = true;\
      } \
    } else { *success = true; } \
  } while (0)
#else
#define __memread_status(out, r, ptr, success) do { \
    *success = false; \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      co_yield __scratchvar(sc); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out != (__u64)-1) { \
        *success = true;\
      } \
    } else { *success = true; } \
  } while (0)

#endif

#define __memread(out, r, ptr) do { \
    hsyscall __scratchvar(sc); \
    out = (__typeof__(out)) memread(r, (__u64)ptr, &__scratchvar(sc)); \
    if ((__u64)out == (__u64)-1) { \
      co_yield __scratchvar(sc); \
      out = (__typeof__(out)) memread(r, (__u64)ptr, nullptr); \
      if ((__u64)out == (__u64)-1) { \
        printf("FATAL: cannot read %lx\n", (long unsigned int)ptr); fflush(NULL); \
        assert(0 && "memory read failed"); \
      } \
    } \
  } while (0)

//hsyscall* _allocate_hsyscall();

#define map_guest_pointer_status(details, varname, ptr, success) __memread_status(varname, details, ptr, success)
#define map_guest_pointer(details, varname, ptr) __memread(varname, details, ptr)

#define yield_syscall(r, ...) (build_syscall(&r->scratch, __VA_ARGS__), (co_yield r->scratch), r->retval)
#define get_regs_or_die(details, outregs) if (getregs(details, outregs) != 0) { printf("getregs failure\n"); co_return;};

void dump_sc(struct kvm_regs r) {
#ifndef WINDOWS
  // LINUX
  printf("Callno %lld (%llx, %llx, %llx, %llx, %llx, %llx)\n", CALLNO(r),
        ARG0(r), ARG1(r), ARG2(r), ARG3(r), ARG4(r), ARG5(r));
#else
  // Windows
  printf("Callno %lld (%llx, %llx, %llx, %llx)\n", CALLNO(r),
        r.r10, r.rdx, r.r8, r.r9);
#endif
}


void dump_sc_with_stack(asid_details* a, struct kvm_regs r) {
  dump_sc(r);
  // Dump stack too!
  unsigned long int *stack;
  stack = (unsigned long int*)memread(a, r.rsp, nullptr);
#ifdef WINDOWS
  for (int i=0; i < 10; i++) {
#else
    if (0) { // TODO linux stack based logging
      int i = 0;
#endif
    printf("\t - Stack[%d] = %lx\n", i, stack[i]);
  }
}

void dump_regs(struct kvm_regs r) {
  printf("PC: %016llx    RAX: %016llx    RBX %016llx    RCX %016llx    RDX %016llx   RSI %016llx   RDI %016llx   RSP %016llx\n",
      r.rip, r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rsp);
  printf("\t RBP: %016llx    R8 %016llx    R9 %016llx    R10 %016llx    R11 %016llx    R12 %016llx    R13 %016llx\n", r.rbp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13);
  printf("\t R14: %016llx    R15: %016llx    RFLAGS %016llx\n", r.r14, r.r15, r.rflags);
}


// create_coopt_t type takes in asid_details*, returns SysCoroutine
typedef SyscCoroutine(create_coopt_t)(asid_details*);
typedef create_coopt_t*(coopter_f)(void*, long unsigned int, long unsigned int, unsigned int);

// Function *a capability must provide* -  extern C to avoid mangling
// Returns a pointer to a local (extern C) coroutine function if the syscall should be co-opted, otherwise NULL
extern "C" {
  create_coopt_t* should_coopt(void*cpu, long unsigned int callno, long unsigned int pc, unsigned int asid);
}

#endif
