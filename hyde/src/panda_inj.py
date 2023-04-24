from pandare import Panda, PyPlugin
from dataclasses import dataclass
import os

# We don't have an OSI profile for jammy :(
#panda = Panda("x86_64", mem="1G", expect_prompt=rb"ubuntu@ubuntu:~/.*\$", qcow="/home/andrew/.panda/ubuntu-jammy.qcow", ...)


# NEW IDEA _ WIP
# We're okay when we see a syscall insn and, after emulating it, we change thigns
# But when we set a new PC of the sysclal instruction and wait for the guest to hit it again, the target could get a signal before
# it hits the syscall - and then we'd have set up registers for a subsequent syscall injection (i.e., we have magic and our key),
# but syscalls get run in the syscall handler - which may or may not clobber our registers (if it does it has to clean them up though?)

# IDEA: In one of our registers, encode something with the syscall insn's PC: then on syscalls we check if the magic values are valid for the syscall insns's PC.
# If so, we're in good shape (or the syscall handler hit the exact same code, but let's ignore that case) otherwise we're in a signal handler with junk registers and
# we don't care!

#       Value from syscall->sysret | Value from sysret->syscall for injection
# magic1 = 0xdeadbeef             | 0xb1ade000              KVM:R14
# magic2 = key                    | key^syscall_pc          KVM:R15
# magic3 = unused                 | key                     KVM:R12
# magic4 = unused                 | syscall_pc              KVM:R13

# On syscall, if we see b1ade000 in magic1, we check for a valid hash - if we have one, registers were left intact
# and then we check if the saved syscall pc matches the pc of the current syscall instruction. If so, we're not in a signal handler - we modify magic1 to be deadbeef
# and set up the injected syscall to run (i.e., set RAX to the new callno). Otherwise, we're in a signal handler and we must *not* do anything

syscalls={0:"read",1:"write",2:"open",3:"close",4:"stat",5:"fstat",6:"lstat",7:"poll",8:"lseek",9:"mmap",10:"mprotect",11:"munmap",12:"brk",13:"rt_sigaction",14:"rt_sigprocmask",15:"rt_sigreturn",16:"ioctl",17:"pread64",18:"pwrite64",19:"readv",20:"writev",21:"access",22:"pipe",23:"select",24:"sched_yield",25:"mremap",26:"msync",27:"mincore",28:"madvise",29:"shmget",30:"shmat",31:"shmctl",32:"dup",33:"dup2",34:"pause",35:"nanosleep",36:"getitimer",37:"alarm",38:"setitimer",39:"getpid",40:"sendfile",41:"socket",42:"connect",43:"accept",44:"sendto",45:"recvfrom",46:"sendmsg",47:"recvmsg",48:"shutdown",49:"bind",50:"listen",51:"getsockname",52:"getpeername",53:"socketpair",54:"setsockopt",55:"getsockopt",56:"clone",57:"fork",58:"vfork",59:"execve",60:"exit",61:"wait4",62:"kill",63:"uname",64:"semget",65:"semop",66:"semctl",67:"shmdt",68:"msgget",69:"msgsnd",70:"msgrcv",71:"msgctl",72:"fcntl",73:"flock",74:"fsync",75:"fdatasync",76:"truncate",77:"ftruncate",78:"getdents",79:"getcwd",80:"chdir",81:"fchdir",82:"rename",83:"mkdir",84:"rmdir",85:"creat",86:"link",87:"unlink",88:"symlink",89:"readlink",90:"chmod",91:"fchmod",92:"chown",93:"fchown",94:"lchown",95:"umask",96:"gettimeofday",97:"getrlimit",98:"getrusage",99:"sysinfo",100:"times",101:"ptrace",102:"getuid",103:"syslog",104:"getgid",105:"setuid",106:"setgid",107:"geteuid",108:"getegid",109:"setpgid",110:"getppid",111:"getpgrp",112:"setsid",113:"setreuid",114:"setregid",115:"getgroups",116:"setgroups",117:"setresuid",118:"getresuid",119:"setresgid",120:"getresgid",121:"getpgid",122:"setfsuid",123:"setfsgid",124:"getsid",125:"capget",126:"capset",127:"rt_sigpending",128:"rt_sigtimedwait",129:"rt_sigqueueinfo",130:"rt_sigsuspend",131:"sigaltstack",132:"utime",133:"mknod",134:"uselib",135:"personality",136:"ustat",137:"statfs",138:"fstatfs",139:"sysfs",140:"getpriority",141:"setpriority",142:"sched_setparam",143:"sched_getparam",144:"sched_setscheduler",145:"sched_getscheduler",146:"sched_get_priority_max",147:"sched_get_priority_min",148:"sched_rr_get_interval",149:"mlock",150:"munlock",151:"mlockall",152:"munlockall",153:"vhangup",154:"modify_ldt",155:"pivot_root",156:"_sysctl",157:"prctl",158:"arch_prctl",159:"adjtimex",160:"setrlimit",161:"chroot",162:"sync",163:"acct",164:"settimeofday",165:"mount",166:"umount2",167:"swapon",168:"swapoff",169:"reboot",170:"sethostname",171:"setdomainname",172:"iopl",173:"ioperm",174:"create_module",175:"init_module",176:"delete_module",177:"get_kernel_syms",178:"query_module",179:"quotactl",180:"nfsservctl",181:"getpmsg",182:"putpmsg",183:"afs_syscall",184:"tuxcall",185:"security",186:"gettid",187:"readahead",188:"setxattr",189:"lsetxattr",190:"fsetxattr",191:"getxattr",192:"lgetxattr",193:"fgetxattr",194:"listxattr",195:"llistxattr",196:"flistxattr",197:"removexattr",198:"lremovexattr",199:"fremovexattr",200:"tkill",201:"time",202:"futex",203:"sched_setaffinity",204:"sched_getaffinity",205:"set_thread_area",206:"io_setup",207:"io_destroy",208:"io_getevents",209:"io_submit",210:"io_cancel",211:"get_thread_area",212:"lookup_dcookie",213:"epoll_create",214:"epoll_ctl_old",215:"epoll_wait_old",216:"remap_file_pages",217:"getdents64",218:"set_tid_address",219:"restart_syscall",220:"semtimedop",221:"fadvise64",222:"timer_create",223:"timer_settime",224:"timer_gettime",225:"timer_getoverrun",226:"timer_delete",227:"clock_settime",228:"clock_gettime",229:"clock_getres",230:"clock_nanosleep",231:"exit_group",232:"epoll_wait",233:"epoll_ctl",234:"tgkill",235:"utimes",236:"vserver",237:"mbind",238:"set_mempolicy",239:"get_mempolicy",240:"mq_open",241:"mq_unlink",242:"mq_timedsend",243:"mq_timedreceive",244:"mq_notify",245:"mq_getsetattr",246:"kexec_load",247:"waitid",248:"add_key",249:"request_key",250:"keyctl",251:"ioprio_set",252:"ioprio_get",253:"inotify_init",254:"inotify_add_watch",255:"inotify_rm_watch",256:"migrate_pages",257:"openat",258:"mkdirat",259:"mknodat",260:"fchownat",261:"futimesat",262:"newfstatat",263:"unlinkat",264:"renameat",265:"linkat",266:"symlinkat",267:"readlinkat",268:"fchmodat",269:"faccessat",270:"pselect6",271:"ppoll",272:"unshare",273:"set_robust_list",274:"get_robust_list",275:"splice",276:"tee",277:"sync_file_range",278:"vmsplice",279:"move_pages",280:"utimensat",281:"epoll_pwait",282:"signalfd",283:"timerfd_create",284:"eventfd",285:"fallocate",286:"timerfd_settime",287:"timerfd_gettime",288:"accept4",289:"signalfd4",290:"eventfd2",291:"epoll_create1",292:"dup3",293:"pipe2",294:"inotify_init1",295:"preadv",296:"pwritev",297:"rt_tgsigqueueinfo",298:"perf_event_open",299:"recvmmsg",300:"fanotify_init",301:"fanotify_mark",302:"prlimit64",303:"name_to_handle_at",304:"open_by_handle_at",305:"clock_adjtime",306:"syncfs",307:"sendmmsg",308:"setns",309:"getcpu",310:"process_vm_readv",311:"process_vm_writev",312:"kcmp",313:"finit_module",
314: "sys_sched_setattr", 315:"sys_sched_getattr", 316:"sys_renameat2", 317:"sys_seccomp", 318:"sys_getrandom", 319:"sys_memfd_create", 320:"sys_kexec_file_load", 321:"sys_bpf", 322:"stub_execveat", 323:"userfaultfd", 324:"membarrier", 325:"mlock2", 326:"copy_file_range", 327:"preadv2", 328:"pwritev2", 329:"pkey_mprotect", 330:"pkey_alloc", 331:"pkey_free", 332:"statx", 333:"io_pgetevents", 334:"rseq", 335:"pkey_mprotect" }
for x in range(1000):
    if x not in syscalls:
        syscalls[x] = f"??? ({x})"

# We set magic value on a syscall - at the sysret we look for it
MAGIC_VALUE = 0xdeadbeee

# We set magic value repeat on a sysret when we're going back to a syscall
# we also clobber a bunch of registers to ensure we don't accidentally inject into a singal
# handler
MAGIC_VALUE_REPEAT = 0xb1ade001
MAGIC1="R12"
MAGIC2="R13"
MAGIC3="R14"
MAGIC4="R15"


def dprint(s): # DEBUG TOGGLE
    if False:
        print(s)

def get_pid_tid(panda, cpu):
    current_proc = panda.plugins['osi'].get_current_process(cpu)
    assert(current_proc != panda.ffi.NULL)
    pid = current_proc.pid

    current_thread = panda.plugins['osi'].get_current_thread(cpu)
    assert(current_thread != panda.ffi.NULL)
    tid = current_thread.tid

    return (pid, tid)



# Simple dataclass
@dataclass
class CallInfo():
    magic1: int
    magic2: int
    magic3: int

    callno: int

    pid: int
    tid: int

    ctr: int
    pending: int

    def __init__(self, panda, cpu):
        # Store original registers + original process info
        self.callno = panda.arch.get_reg(cpu, "RAX")
        self.magic1 = panda.arch.get_reg(cpu, MAGIC1)
        self.magic2 = panda.arch.get_reg(cpu, MAGIC2)
        self.magic3 = panda.arch.get_reg(cpu, MAGIC3)
        self.magic4 = panda.arch.get_reg(cpu, MAGIC4)
        self.pid, self.tid = get_pid_tid(panda, cpu)

        self.ctr = 0
        self.pending = 0

    def restore_registers(self, panda, cpu):
        '''
        On return of a coopted syscall or at the start
        of a reinjected syscall, restore original magic1-3

        Note we never restore RAX explicitly
        '''
        panda.arch.set_reg(cpu, MAGIC1, self.magic1)
        panda.arch.set_reg(cpu, MAGIC2, self.magic2)
        panda.arch.set_reg(cpu, MAGIC3, self.magic3)
        panda.arch.set_reg(cpu, MAGIC4, self.magic4)

    def inject_syscall(self, panda, cpu, callno, key):
        '''
        At a syscall we want to change to call callno.
        On return we'll find a handle to this with key
        and restore MAGIC1, MAGIC2
        '''

        panda.arch.set_reg(cpu, MAGIC1, MAGIC_VALUE)
        panda.arch.set_reg(cpu, MAGIC2, key)
        panda.arch.set_reg(cpu, "RAX", callno)
        self.pending = 1

    def __str__(self):
        return f"CallInfo(MAGIC1={self.magic1:x}, MAGIC2={self.magic2:x}, MAGIC3={self.magic3:x}, callno={self.callno}, pid={self.pid}, tid={self.tid}, ctr={self.ctr}, pending={self.pending})"

class SysInject(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.register_data = {}  # unique, per syscall key -> CallInfo

        # Init at a sort of unique value so we can eyeball it later
        self.ctr_base = 0xd00d000
        self.ctr = self.ctr_base

        # How many times did we see had syscalls within syscalls?
        self.waitc = 0

        '''
        @panda.cb_before_block_exec
        def bbe(cpu, tb):
            if not panda.in_kernel(cpu):
                if panda.arch.get_reg(cpu, "R14") == MAGIC_VALUE:
                    #print(f"\nBBE at {panda.current_pc(cpu):x} magic R14")
                    #panda.arch.dump_regs(cpu)

                    if panda.arch.get_reg(cpu, "R15") not in self.register_data:
                        print(f"\n\nFATAL in BBE at {panda.current_pc(cpu):x} magic R14 but unexpected R15: {panda.arch.get_reg(cpu, 'R15'):x}")
                        panda.end_analysis()
        '''

        @panda.ppp("syscalls2", "on_all_sys_enter")
        def on_syscall(cpu, pc, callno):
            #if callno == 15:
            #    print(f"SIGRETURN in {self.panda.get_process_name(cpu)}")

            if callno in [  
                                56, # clone
                                435, # clone3
                                57, # fork
                                58, # vfork
                                # noreturn: allowed we can inject into exit/exit_group, but unless they fail, we'll never see them return and we'll leak memory
                                60, # exit
                                231, # exit_group
                                # noreturn: prohibited - we can't cleanup R14/R15 for these
                                15, # sigreturn - This doesn't return, but we'll keep thinking we're waiting on a ret for it, leaking memory and eventually asserting becasue too many pending syscalls for a proc
                                59, # execve
                                322, # execveat
                            ]:
                return

            #rax = panda.arch.get_reg(cpu, "RAX")
            #r13 = panda.arch.get_reg(cpu, "R13")
            #r14 = panda.arch.get_reg(cpu, "R14")
            #r15 = panda.arch.get_reg(cpu, "R15")
            pid, tid = get_pid_tid(panda, cpu)

            if not self.handle_reinjection(cpu, pc):

                # New injection
                key = self.ctr
                self.ctr += 1


                dprint(f"\n{pid},{tid} COOPT at CALL {syscalls[callno]} pc={pc:x}. Change to GETPID")
                self.register_data[key] = CallInfo(self.panda, cpu)

                if callno > 400:
                    print("BAD CALLNO - bail")
                    self.panda.end_analysis()
                    import os
                    os._exit(1)
                    return

                #print(f"BEFORE {key:x}: {self.register_data[key]}")
                #self.panda.arch.dump_regs(cpu)

                # Clobber registers to store callno=GETPID and our key in magic
                self.register_data[key].inject_syscall(self.panda, cpu, 39, key)
                #self.inject_syscall(cpu, self.register_data[key].callno, key) # No-op, seems to work

        # Manually identified address for just before a sysert (kernel block ending with sysretq)
        @panda.hook(0xffffffff81a00152)
        def hook_sysret(cpu, tb, h):
            # This block is the syscall return
            if self.panda.arch.get_reg(cpu, MAGIC1) == MAGIC_VALUE:
                try:
                    self.on_sysret(cpu, panda.arch.get_reg(cpu, "RCX"), None)
                except Exception as e:
                    print("ON_SYSRET EXN:", e)
                    panda.end_analysis()

    def handle_reinjection(self, cpu, pc):
        if self.panda.arch.get_reg(cpu, MAGIC1) != MAGIC_VALUE_REPEAT:
            return False

        cur_magic = self.get_magic_values(cpu)
        if cur_magic is None:
            print(f"bad reinjection at {pc:x}")
            return False

        (key, expected_pc) = cur_magic

        if expected_pc != pc:
            print(f"On syscall we have magic values but for another PC: At {pc:x} vs magic {expected_pc:x}")
            return False

        # By here we're confident that we matched
        pid, tid = get_pid_tid(self.panda, cpu)
        dprint(f"\n{pid},{tid} REINJECT at syscall pc={pc:x}. Restore callno to {syscalls[self.register_data[key].callno]}")

        # If key is unknown, fatal error
        if key not in self.register_data:
            print(f"\n\nFATAL: key {key:x} not in data but recovered from magic (current key ctr = {self.ctr:x})")
            print(f"In process {self.panda.get_process_name(cpu)}: {pid},{tid} at {pc:x}")
            panda.arch.dump_regs(cpu)
            self.panda.end_analysis()
            return
        
        # If this syscall is pending, fatal error
        if self.register_data[key].pending == 1:
            # New design should never have nested syscalls
            print("FATAL this shouldn't be possible?")
            panda.end_analysis()
            return

        # First print the results of injecting getpid - it should match what we get from OSI!
        injected_rv = self.panda.from_unsigned_guest(self.panda.arch.get_reg(cpu, "RAX"))
        if injected_rv != pid:
            print(f"Unexpected return from injected getpid: got {injected_rv} expected {pid}")

        # "Advance coopter" by running the originally requested syscall
        # First we undo our syscall->sysret injection components

        self.register_data[key].ctr += 1 # Turn that 0 into a 1 so on return we see that we've finished

        # Undo our sysret->syscall injection components. RAX is still changed
        self.register_data[key].restore_registers(self.panda, cpu)

        # And then setup the original syscall - RAX is changed and magic1..2 are set
        self.register_data[key].inject_syscall(self.panda, cpu, self.register_data[key].callno, key)

        return True # We're doing a reinjection


    # On sysret, restore R14, R15
    def on_sysret(self, cpu, pc, panda_callno=None):
        # Only called when MAGIC1 is MAGIC_VALUE, MAGIC2 has key
        key = self.panda.arch.get_reg(cpu, MAGIC2)

        retval = self.panda.arch.get_arg(cpu, 0, convention="syscall")
        pid, tid = get_pid_tid(self.panda, cpu)
        dprint(f"{pid},{tid}: SYSRET for {key:x} after some injection retval={retval} (decimal)")

        done = False
        fail = None
        try:
            saved = self.register_data[key]
        except KeyError:
            fail = f"Key {key:x} not found in self.register_data"

        if not fail:
            if (saved.pending !=1 ):
                fail = "Return with pending of 0"
            self.register_data[key].pending = 0

            if saved.ctr == 1:
                done = True
                dprint(f"FREE register_data for {key:x}")
                del self.register_data[key]

            if pid != saved.pid:
                fail = f"PID changed from {saved.pid} to {pid}"

            if tid != saved.tid:
                fail = f"tid changed from {saved.tid} to {tid}"

        if fail is not None:
            print("FATAL " + fail)
            self.panda.end_analysis()

        if not done:
            # We need to go back to the syscall at pc-2. Here we set the registers in our new way
            dprint(f"\t{key:x} has more to inject, go back to {pc-2:x}")
            self.set_magic_values(cpu, key, pc-2) # Set process to go back to syscall insn at pc-2 with magic values

        else:
            # All done, cleanup and restore magic valuesc
            saved.restore_registers(self.panda, cpu)

    def set_magic_values(self, cpu, key, expected_pc):
        # When we're injecting a syscall from a sysret we need to be precise to make sure we ignore any signal handlers
        # that end up with our magic values. We do this by setting multiple registers to checksum each other and
        # encoding the target syscall pc (and maybe SP) in our values. This way we can check if 1) they're changed
        # or 2) we're in the wrong place. After the signal handler finishes, it should(?) restore registers
        # and return to our syscall instruction.

        # SAFETY note: if we're doing an inject like fd=open(x), read(fd), close(fd) and a signal handler runs
        # in the middle, it could see the changed state
        
        self.panda.arch.set_reg(cpu, MAGIC1, MAGIC_VALUE_REPEAT)
        self.panda.arch.set_reg(cpu, MAGIC2, key)
        self.panda.arch.set_reg(cpu, MAGIC3, expected_pc)
        self.panda.arch.set_reg(cpu, MAGIC4, key ^ expected_pc)

        # And set RCX so we actually go back to expected PC
        self.panda.arch.set_reg(cpu, "RCX", expected_pc)

    def get_magic_values(self, cpu):
       '''
       Do the current registers contain a valid magic? If not return None
       Otherwise return (key, expected_pc)
       '''
       m1 = self.panda.arch.get_reg(cpu, MAGIC1)
       m2 = self.panda.arch.get_reg(cpu, MAGIC2)
       m3 = self.panda.arch.get_reg(cpu, MAGIC3)
       m4 = self.panda.arch.get_reg(cpu, MAGIC4)

       if m1 != MAGIC_VALUE_REPEAT:
           return None
       if m2 ^ m3 != m4:
           print("XXX IT HAPPENDD - HASH DIVERGENCE -> IGNORING ALLEGED MAGIC") # Whoop, our newest idea saved us
           self.panda.arch.dump_regs(cpu)
           return None
       
       return (m2, m3)



import capstone
class InsnLogger(PyPlugin):
    def __init__(self, panda):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        log_f = open("insns2.txt", "w")
        insn_cache = {} # asid -> address -> disassembly string

        def generate_insns(cpu, tb):
            # Disassemble each basic block and store in insn_cache
            asid = panda.current_asid(cpu)

            if asid not in insn_cache:
                insn_cache[asid] = {}

            if tb.pc in insn_cache[asid]:
                #assert(len(insn_cache[asid][tb.pc]))
                return
            
            code = panda.virtual_memory_read(cpu, tb.pc, tb.size)

            insn_cache[asid][tb.pc] = ""

            for i in md.disasm(code, tb.pc):
                insn_cache[asid][tb.pc] += ("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))

        @panda.cb_after_block_translate
        def before_block_trans(cpu, tb):
            # Before we translate each block in find cache its disassembly
            generate_insns(cpu, tb)

        @panda.cb_before_block_exec
        def before_block_exec(cpu, tb):
            asid = panda.current_asid(cpu)
            pc = panda.current_pc(cpu)
            if pc == 0:
                return

            if asid not in insn_cache or tb.pc not in insn_cache[asid]: # If we miss the cache, update it
                generate_insns(cpu, tb)
        
            if asid not in insn_cache or tb.pc not in insn_cache[asid]: # If we miss the cache, update it
                log_f.write(f"At {pc:x} but insn_cache is empty for block {tb.pc:x}\n")
                return

            pid, tid = get_pid_tid(panda, cpu)
            log_f.write(f"\n{pid:x}, {tid:x} at pc {pc:x}\n" + insn_cache[asid][tb.pc])


if __name__ == "__main__":
    panda = Panda(generic="x86_64")

    # Not sure if this changes anything?
    panda.disable_tb_chaining() # After sysret we need to jump to the PC we set, chaining would be bad
    panda.enable_precise_pc()

    #panda.load_plugin("syscalls2", {"load-info": True})
    #panda.load_plugin("syscalls_logger", {"target": "bash"})
    #panda.load_plugin("syscalls_logger")

    panda.load_plugin("syscalls2", {"load-info": False})

    panda.pyplugins.load(SysInject)
    #panda.pyplugins.load(InsnLogger)

    @panda.queue_blocking
    def driver():
        #panda.record_cmd("whoami", recording_name="whoami", snap_name="coreutils")

        # Need to add cflag, otherwise it won't build with the 18.04 installed compiler, even unmodified
        """
        time make check SUBDIRS=. -j$(nproc)
        """
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. VERBOSE=yes" # OOMs on my dev machine :(
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/tail-2/inotify-race SUBDIRS=. VERBOSE=yes; cat tests/tail-2/inotify-race.log" # Skip, bkp not hit
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/rm/r-root SUBDIRS=. VERBOSE=yes; cat tests/rm/r-root.log"
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. VERBOSE=yes"
        cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/misc/printf-quote SUBDIRS=. VERBOSE=yes"

        panda.revert_sync("coreutils3")

        #panda.run_monitor_cmd("begin_record coreutils")
        #out = panda.run_serial_cmd(cmd, timeout=60*100)
        #panda.run_monitor_cmd("end_record")
        #print(out[-1000:])

        #print(panda.run_serial_cmd("strace whoami", timeout=600))
        out = panda.run_serial_cmd(cmd, timeout=600)
        print("\n".join([x for x in out.split("\n") if len(x)]))
        panda.end_analysis()

    panda.run()