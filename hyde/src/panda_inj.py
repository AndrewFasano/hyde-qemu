from pandare import Panda, PyPlugin
from dataclasses import dataclass
import os

# We don't have an OSI profile for jammy :(
#panda = Panda("x86_64", mem="1G", expect_prompt=rb"ubuntu@ubuntu:~/.*\$", qcow="/home/andrew/.panda/ubuntu-jammy.qcow", ...)

syscalls={0:"read",1:"write",2:"open",3:"close",4:"stat",5:"fstat",6:"lstat",7:"poll",8:"lseek",9:"mmap",10:"mprotect",11:"munmap",12:"brk",13:"rt_sigaction",14:"rt_sigprocmask",15:"rt_sigreturn",16:"ioctl",17:"pread64",18:"pwrite64",19:"readv",20:"writev",21:"access",22:"pipe",23:"select",24:"sched_yield",25:"mremap",26:"msync",27:"mincore",28:"madvise",29:"shmget",30:"shmat",31:"shmctl",32:"dup",33:"dup2",34:"pause",35:"nanosleep",36:"getitimer",37:"alarm",38:"setitimer",39:"getpid",40:"sendfile",41:"socket",42:"connect",43:"accept",44:"sendto",45:"recvfrom",46:"sendmsg",47:"recvmsg",48:"shutdown",49:"bind",50:"listen",51:"getsockname",52:"getpeername",53:"socketpair",54:"setsockopt",55:"getsockopt",56:"clone",57:"fork",58:"vfork",59:"execve",60:"exit",61:"wait4",62:"kill",63:"uname",64:"semget",65:"semop",66:"semctl",67:"shmdt",68:"msgget",69:"msgsnd",70:"msgrcv",71:"msgctl",72:"fcntl",73:"flock",74:"fsync",75:"fdatasync",76:"truncate",77:"ftruncate",78:"getdents",79:"getcwd",80:"chdir",81:"fchdir",82:"rename",83:"mkdir",84:"rmdir",85:"creat",86:"link",87:"unlink",88:"symlink",89:"readlink",90:"chmod",91:"fchmod",92:"chown",93:"fchown",94:"lchown",95:"umask",96:"gettimeofday",97:"getrlimit",98:"getrusage",99:"sysinfo",100:"times",101:"ptrace",102:"getuid",103:"syslog",104:"getgid",105:"setuid",106:"setgid",107:"geteuid",108:"getegid",109:"setpgid",110:"getppid",111:"getpgrp",112:"setsid",113:"setreuid",114:"setregid",115:"getgroups",116:"setgroups",117:"setresuid",118:"getresuid",119:"setresgid",120:"getresgid",121:"getpgid",122:"setfsuid",123:"setfsgid",124:"getsid",125:"capget",126:"capset",127:"rt_sigpending",128:"rt_sigtimedwait",129:"rt_sigqueueinfo",130:"rt_sigsuspend",131:"sigaltstack",132:"utime",133:"mknod",134:"uselib",135:"personality",136:"ustat",137:"statfs",138:"fstatfs",139:"sysfs",140:"getpriority",141:"setpriority",142:"sched_setparam",143:"sched_getparam",144:"sched_setscheduler",145:"sched_getscheduler",146:"sched_get_priority_max",147:"sched_get_priority_min",148:"sched_rr_get_interval",149:"mlock",150:"munlock",151:"mlockall",152:"munlockall",153:"vhangup",154:"modify_ldt",155:"pivot_root",156:"_sysctl",157:"prctl",158:"arch_prctl",159:"adjtimex",160:"setrlimit",161:"chroot",162:"sync",163:"acct",164:"settimeofday",165:"mount",166:"umount2",167:"swapon",168:"swapoff",169:"reboot",170:"sethostname",171:"setdomainname",172:"iopl",173:"ioperm",174:"create_module",175:"init_module",176:"delete_module",177:"get_kernel_syms",178:"query_module",179:"quotactl",180:"nfsservctl",181:"getpmsg",182:"putpmsg",183:"afs_syscall",184:"tuxcall",185:"security",186:"gettid",187:"readahead",188:"setxattr",189:"lsetxattr",190:"fsetxattr",191:"getxattr",192:"lgetxattr",193:"fgetxattr",194:"listxattr",195:"llistxattr",196:"flistxattr",197:"removexattr",198:"lremovexattr",199:"fremovexattr",200:"tkill",201:"time",202:"futex",203:"sched_setaffinity",204:"sched_getaffinity",205:"set_thread_area",206:"io_setup",207:"io_destroy",208:"io_getevents",209:"io_submit",210:"io_cancel",211:"get_thread_area",212:"lookup_dcookie",213:"epoll_create",214:"epoll_ctl_old",215:"epoll_wait_old",216:"remap_file_pages",217:"getdents64",218:"set_tid_address",219:"restart_syscall",220:"semtimedop",221:"fadvise64",222:"timer_create",223:"timer_settime",224:"timer_gettime",225:"timer_getoverrun",226:"timer_delete",227:"clock_settime",228:"clock_gettime",229:"clock_getres",230:"clock_nanosleep",231:"exit_group",232:"epoll_wait",233:"epoll_ctl",234:"tgkill",235:"utimes",236:"vserver",237:"mbind",238:"set_mempolicy",239:"get_mempolicy",240:"mq_open",241:"mq_unlink",242:"mq_timedsend",243:"mq_timedreceive",244:"mq_notify",245:"mq_getsetattr",246:"kexec_load",247:"waitid",248:"add_key",249:"request_key",250:"keyctl",251:"ioprio_set",252:"ioprio_get",253:"inotify_init",254:"inotify_add_watch",255:"inotify_rm_watch",256:"migrate_pages",257:"openat",258:"mkdirat",259:"mknodat",260:"fchownat",261:"futimesat",262:"newfstatat",263:"unlinkat",264:"renameat",265:"linkat",266:"symlinkat",267:"readlinkat",268:"fchmodat",269:"faccessat",270:"pselect6",271:"ppoll",272:"unshare",273:"set_robust_list",274:"get_robust_list",275:"splice",276:"tee",277:"sync_file_range",278:"vmsplice",279:"move_pages",280:"utimensat",281:"epoll_pwait",282:"signalfd",283:"timerfd_create",284:"eventfd",285:"fallocate",286:"timerfd_settime",287:"timerfd_gettime",288:"accept4",289:"signalfd4",290:"eventfd2",291:"epoll_create1",292:"dup3",293:"pipe2",294:"inotify_init1",295:"preadv",296:"pwritev",297:"rt_tgsigqueueinfo",298:"perf_event_open",299:"recvmmsg",300:"fanotify_init",301:"fanotify_mark",302:"prlimit64",303:"name_to_handle_at",304:"open_by_handle_at",305:"clock_adjtime",306:"syncfs",307:"sendmmsg",308:"setns",309:"getcpu",310:"process_vm_readv",311:"process_vm_writev",312:"kcmp",313:"finit_module",
314: "sys_sched_setattr", 315:"sys_sched_getattr", 316:"sys_renameat2", 317:"sys_seccomp", 318:"sys_getrandom", 319:"sys_memfd_create", 320:"sys_kexec_file_load", 321:"sys_bpf", 322:"stub_execveat", 323:"userfaultfd", 324:"membarrier", 325:"mlock2", 326:"copy_file_range", 327:"preadv2", 328:"pwritev2", 329:"pkey_mprotect", 330:"pkey_alloc", 331:"pkey_free", 332:"statx", 333:"io_pgetevents", 334:"rseq", 335:"pkey_mprotect" }
for x in range(1000):
    if x not in syscalls:
        syscalls[x] = "???"
MAGIC_VALUE = 0xdeadbeee

# Simple dataclass
@dataclass
class CallInfo():
    rax: int
    r13: int
    r14: int
    r15: int
    pid: int
    tid: int
    callno: int
    ctr: int
    pending: int

    def __str__(self):
        return f"CallInfo(rax={self.rax:x} r13={self.r13:x}, r14={self.r14:x}, r15={self.r15:x}, ptid=({self.pid}, {self.tid}), call {syscalls[self.callno]}, ctr={self.ctr})"

def get_pid_tid(panda, cpu):
    current_proc = panda.plugins['osi'].get_current_process(cpu)
    assert(current_proc != panda.ffi.NULL)
    pid = current_proc.pid

    current_thread = panda.plugins['osi'].get_current_thread(cpu)
    assert(current_thread != panda.ffi.NULL)
    tid = current_thread.tid

    return (pid, tid)


class SysInject(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.register_data = {}  # unique, per syscall key -> CallInfo

        # Init at a sort of unique value so we can eyeball it later
        self.ctr_base = 0xd00d000
        self.ctr = self.ctr_base

        # How many times did we see had syscalls within syscalls?
        self.waitc = 0

        #@panda.cb_before_block_exec
        def bbe(cpu, tb):
            if not panda.in_kernel(cpu):
                if panda.arch.get_reg(cpu, "R14") == MAGIC_VALUE:
                    #print(f"\nBBE at {panda.current_pc(cpu):x} magic R14")
                    #panda.arch.dump_regs(cpu)

                    if panda.arch.get_reg(cpu, "R15") not in self.register_data:
                        print(f"\n\nFATAL in BBE at {panda.current_pc(cpu):x} magic R14 but unexpected R15: {panda.arch.get_reg(cpu, 'R15'):x}")
                        panda.end_analysis()

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

            rax = panda.arch.get_reg(cpu, "RAX")
            r13 = panda.arch.get_reg(cpu, "R13")
            r14 = panda.arch.get_reg(cpu, "R14")
            r15 = panda.arch.get_reg(cpu, "R15")
            pid, tid = get_pid_tid(panda, cpu)

            if r15 == MAGIC_VALUE:
                # We're in the middle of doing an injection, advance counter, restore RAX
                key = r13

                if r13 != r14:
                    print(f"\n\nWARN: r15 and r13 redundancy disagree on syscall")
                    print(f"In process {self.panda.get_process_name(cpu)}: {pid},{tid} at {pc:x}")
                    panda.arch.dump_regs(cpu)
                    #self.panda.end_analysis()
                    #return

                if key not in self.register_data:
                    print(f"\n\nFATAL: key {key:x} not in data but have magic register (current key = {self.ctr:x})")
                    print(f"In process {self.panda.get_process_name(cpu)}: {pid},{tid} at {pc:x}")
                    panda.arch.dump_regs(cpu)
                    self.panda.end_analysis()
                    return
                
                if self.register_data[key].pending == 1:
                    # We're waiting for this syscall to return - this must be a nested syscall!
                    # Create a new key and object based on the original values(?) not sure they'd ever actually matter?

                    orig = self.register_data[key]
                    key = self.ctr
                    self.ctr += 1

                    self.register_data[key] = CallInfo(orig.rax, orig.r13, orig.r14, orig.r15, pid, tid, callno, orig.ctr+1, 1)
                    print("NESTED SYSCALL")
                    print(f"Original: {orig}")
                    print(f"Child: {self.register_data[key]}")

                    self.panda.arch.set_reg(cpu, "RAX", 39) # GETPID
                    self.panda.arch.set_reg(cpu, "R13", key) # Redundant
                    self.panda.arch.set_reg(cpu, "R14", key)
                    self.panda.arch.set_reg(cpu, "R15", MAGIC_VALUE)

                else:
                    # Restore RAX (we clobbered to inject getpid)
                    self.register_data[key].ctr = 1
                    self.panda.arch.set_reg(cpu, "RAX", self.register_data[key].rax)
                    self.register_data[key].pending=1

                #print(f"INCREMENT (last rv {panda.from_unsigned_guest(rax)}) {pid},{tid} at {pc:x}")
                #print(self.register_data[key])

            else:
                # New injection
                key = self.ctr
                self.ctr += 1

                #print(f"\nPANDA CALL {syscalls[callno]} for {pid},{tid} at {pc:x}")

                if r14 == MAGIC_VALUE:
                    print("ERROR, can't inject on top of magic")
                    self.panda.end_analysis()
                
                self.register_data[key] = CallInfo(rax, r13, r14, r15, pid, tid, callno, 0, 1)

                # Clobber RAX to become inject getpid
                #print(f"CLOBBER {pid},{tid} at {pc:x}, change callno {rax} to getpid")
                self.panda.arch.set_reg(cpu, "RAX", 39) # GETPID
                self.panda.arch.set_reg(cpu, "R13", key) # Redundant
                self.panda.arch.set_reg(cpu, "R14", key)
                self.panda.arch.set_reg(cpu, "R15", MAGIC_VALUE)

        # Manually identified address for just before a sysert (kernel block ending with sysretq)
        @panda.hook(0xffffffff81a00152)
        def hook_sysret(cpu, tb, h):
            # This block is the syscall return
            r14 = self.panda.arch.get_reg(cpu, "R14")
            r15 = self.panda.arch.get_reg(cpu, "R15")
            r13 = self.panda.arch.get_reg(cpu, "R13")
            try:
                if r15 == MAGIC_VALUE:
                    saved = self.register_data[r13]
                    # We're on the sysretq block - we'll jump to RCX (which is the address of the instruction after the syscall)
                    try:
                        self.on_sysret(cpu, panda.arch.get_reg(cpu, "RCX"), saved.callno)
                    except Exception as e:
                        print("XXX XXX \n\n\nXXX\nON_SYSRET EXN:", e)
                        panda.end_analysis()
            except KeyError:
                print(f"SYSRET BAD ID: {r13:x}")
                panda.end_analysis()
                pass

    # On sysret, restore R14, R15
    def on_sysret(self, cpu, pc, panda_callno):
        # Only called when r14 is magic
        r13 = self.panda.arch.get_reg(cpu, "R13")
        r14 = self.panda.arch.get_reg(cpu, "R14")
        r15 = self.panda.arch.get_reg(cpu, "R15")
        #print(f"panda syseret {r14:x},{r15:x}")
        key=r13

        if (r13 != r14):
            print("MISMATCH on return")
            self.panda.arch.dump_regs(cpu)
            self.panda.end_analysis()

        retval = self.panda.arch.get_arg(cpu, 0, convention="syscall")
        pid, tid = get_pid_tid(self.panda, cpu)

        done = False
        fail = None
        try:
            saved = self.register_data[key]
        except KeyError:
            fail = f"Key {key:x} not found in self.register_data"

        if not fail:
            if (saved.pending !=1):
                fail = "Return with pending of 0"
            self.register_data[key].pending = 0

            if saved.ctr == 1:
                done = True
                #print(f"FREE register_data for {key:x}")
                del self.register_data[key]

            if pid != saved.pid:
                fail = f"PID changed from {saved.pid} to {pid}"

            if tid != saved.tid:
                fail = f"tid changed from {saved.tid} to {tid}"

        if fail is not None:
            print("FATAL" + fail)
            panda.end_analysis()

        if not done:
            # We have to go back to the syscall. Leave R14/R15 with magic
            #self.panda.arch.set_reg(cpu, "RAX", saved.rax) # GETPID
            #print(f"REVERT {pid},{tid} to {pc-2:x} (and not {self.panda.arch.get_reg(cpu, 'RCX'):x}) via RCX using key {key:x}")
            #print("Pre revert to syscall:")
            #self.panda.arch.dump_regs(cpu)

            self.panda.arch.set_reg(cpu, "RCX", pc-2)
        else:
            # All done, cleanup and restore r14 and r15

            self.panda.arch.set_reg(cpu, "R13", saved.r13)
            self.panda.arch.set_reg(cpu, "R14", saved.r14)
            self.panda.arch.set_reg(cpu, "R15", saved.r15) # IF they don't match isn't it bad to restore?

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
        #kvm cmd = "make check SUBDIRS=. VERBOSE=yes -j $(nproc)"
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. VERBOSE=yes" # OOMs on my dev machine :(
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/tail-2/inotify-race SUBDIRS=. VERBOSE=yes; cat tests/tail-2/inotify-race.log"
        #test = "make check  SUBDIRS=. VERBOSE=yes"

        cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/tail-2/inotify-race SUBDIRS=. VERBOSE=yes"
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/rm/r-root SUBDIRS=. VERBOSE=yes" # must be non-root
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. VERBOSE=yes"

        # coreutils ./bootstrap'd and ./configured + gdb install
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