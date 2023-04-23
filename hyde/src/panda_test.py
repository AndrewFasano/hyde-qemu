from pandare import Panda
from dataclasses import dataclass
import os

# We don't have an OSI profile for jammy :(
#panda = Panda("x86_64", mem="1G", expect_prompt=rb"ubuntu@ubuntu:~/.*\$", qcow="/home/andrew/.panda/ubuntu-jammy.qcow", ...)

# So I set up a panda 18.04 qcow with coreutils and dependencies pre-installed (setup with kvm, then snapped with panda as "coreutils")
# It's on 18.4.85.108:~andrew/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow
# This script runs the tests in it while doing our r14/r15 magic with syscalls2 and using OSI to track pid/tid at the same time
panda = Panda(generic="x86_64")

MAGIC_VALUE = 0xdeadbeef

TAKE_RECORDING = False # Record normal execution or replay and mess with R14/R15
LOG_INSNS = False

syscalls={0:"read",1:"write",2:"open",3:"close",4:"stat",5:"fstat",6:"lstat",7:"poll",8:"lseek",9:"mmap",10:"mprotect",11:"munmap",12:"brk",13:"rt_sigaction",14:"rt_sigprocmask",15:"rt_sigreturn",16:"ioctl",17:"pread64",18:"pwrite64",19:"readv",20:"writev",21:"access",22:"pipe",23:"select",24:"sched_yield",25:"mremap",26:"msync",27:"mincore",28:"madvise",29:"shmget",30:"shmat",31:"shmctl",32:"dup",33:"dup2",34:"pause",35:"nanosleep",36:"getitimer",37:"alarm",38:"setitimer",39:"getpid",40:"sendfile",41:"socket",42:"connect",43:"accept",44:"sendto",45:"recvfrom",46:"sendmsg",47:"recvmsg",48:"shutdown",49:"bind",50:"listen",51:"getsockname",52:"getpeername",53:"socketpair",54:"setsockopt",55:"getsockopt",56:"clone",57:"fork",58:"vfork",59:"execve",60:"exit",61:"wait4",62:"kill",63:"uname",64:"semget",65:"semop",66:"semctl",67:"shmdt",68:"msgget",69:"msgsnd",70:"msgrcv",71:"msgctl",72:"fcntl",73:"flock",74:"fsync",75:"fdatasync",76:"truncate",77:"ftruncate",78:"getdents",79:"getcwd",80:"chdir",81:"fchdir",82:"rename",83:"mkdir",84:"rmdir",85:"creat",86:"link",87:"unlink",88:"symlink",89:"readlink",90:"chmod",91:"fchmod",92:"chown",93:"fchown",94:"lchown",95:"umask",96:"gettimeofday",97:"getrlimit",98:"getrusage",99:"sysinfo",100:"times",101:"ptrace",102:"getuid",103:"syslog",104:"getgid",105:"setuid",106:"setgid",107:"geteuid",108:"getegid",109:"setpgid",110:"getppid",111:"getpgrp",112:"setsid",113:"setreuid",114:"setregid",115:"getgroups",116:"setgroups",117:"setresuid",118:"getresuid",119:"setresgid",120:"getresgid",121:"getpgid",122:"setfsuid",123:"setfsgid",124:"getsid",125:"capget",126:"capset",127:"rt_sigpending",128:"rt_sigtimedwait",129:"rt_sigqueueinfo",130:"rt_sigsuspend",131:"sigaltstack",132:"utime",133:"mknod",134:"uselib",135:"personality",136:"ustat",137:"statfs",138:"fstatfs",139:"sysfs",140:"getpriority",141:"setpriority",142:"sched_setparam",143:"sched_getparam",144:"sched_setscheduler",145:"sched_getscheduler",146:"sched_get_priority_max",147:"sched_get_priority_min",148:"sched_rr_get_interval",149:"mlock",150:"munlock",151:"mlockall",152:"munlockall",153:"vhangup",154:"modify_ldt",155:"pivot_root",156:"_sysctl",157:"prctl",158:"arch_prctl",159:"adjtimex",160:"setrlimit",161:"chroot",162:"sync",163:"acct",164:"settimeofday",165:"mount",166:"umount2",167:"swapon",168:"swapoff",169:"reboot",170:"sethostname",171:"setdomainname",172:"iopl",173:"ioperm",174:"create_module",175:"init_module",176:"delete_module",177:"get_kernel_syms",178:"query_module",179:"quotactl",180:"nfsservctl",181:"getpmsg",182:"putpmsg",183:"afs_syscall",184:"tuxcall",185:"security",186:"gettid",187:"readahead",188:"setxattr",189:"lsetxattr",190:"fsetxattr",191:"getxattr",192:"lgetxattr",193:"fgetxattr",194:"listxattr",195:"llistxattr",196:"flistxattr",197:"removexattr",198:"lremovexattr",199:"fremovexattr",200:"tkill",201:"time",202:"futex",203:"sched_setaffinity",204:"sched_getaffinity",205:"set_thread_area",206:"io_setup",207:"io_destroy",208:"io_getevents",209:"io_submit",210:"io_cancel",211:"get_thread_area",212:"lookup_dcookie",213:"epoll_create",214:"epoll_ctl_old",215:"epoll_wait_old",216:"remap_file_pages",217:"getdents64",218:"set_tid_address",219:"restart_syscall",220:"semtimedop",221:"fadvise64",222:"timer_create",223:"timer_settime",224:"timer_gettime",225:"timer_getoverrun",226:"timer_delete",227:"clock_settime",228:"clock_gettime",229:"clock_getres",230:"clock_nanosleep",231:"exit_group",232:"epoll_wait",233:"epoll_ctl",234:"tgkill",235:"utimes",236:"vserver",237:"mbind",238:"set_mempolicy",239:"get_mempolicy",240:"mq_open",241:"mq_unlink",242:"mq_timedsend",243:"mq_timedreceive",244:"mq_notify",245:"mq_getsetattr",246:"kexec_load",247:"waitid",248:"add_key",249:"request_key",250:"keyctl",251:"ioprio_set",252:"ioprio_get",253:"inotify_init",254:"inotify_add_watch",255:"inotify_rm_watch",256:"migrate_pages",257:"openat",258:"mkdirat",259:"mknodat",260:"fchownat",261:"futimesat",262:"newfstatat",263:"unlinkat",264:"renameat",265:"linkat",266:"symlinkat",267:"readlinkat",268:"fchmodat",269:"faccessat",270:"pselect6",271:"ppoll",272:"unshare",273:"set_robust_list",274:"get_robust_list",275:"splice",276:"tee",277:"sync_file_range",278:"vmsplice",279:"move_pages",280:"utimensat",281:"epoll_pwait",282:"signalfd",283:"timerfd_create",284:"eventfd",285:"fallocate",286:"timerfd_settime",287:"timerfd_gettime",288:"accept4",289:"signalfd4",290:"eventfd2",291:"epoll_create1",292:"dup3",293:"pipe2",294:"inotify_init1",295:"preadv",296:"pwritev",297:"rt_tgsigqueueinfo",298:"perf_event_open",299:"recvmmsg",300:"fanotify_init",301:"fanotify_mark",302:"prlimit64",303:"name_to_handle_at",304:"open_by_handle_at",305:"clock_adjtime",306:"syncfs",307:"sendmmsg",308:"setns",309:"getcpu",310:"process_vm_readv",311:"process_vm_writev",312:"kcmp",313:"finit_module",
314: "sys_sched_setattr", 315:"sys_sched_getattr", 316:"sys_renameat2", 317:"sys_seccomp", 318:"sys_getrandom", 319:"sys_memfd_create", 320:"sys_kexec_file_load", 321:"sys_bpf", 322:"stub_execveat", 323:"userfaultfd", 324:"membarrier", 325:"mlock2", 326:"copy_file_range", 327:"preadv2", 328:"pwritev2", 329:"pkey_mprotect", 330:"pkey_alloc", 331:"pkey_free", 332:"statx", 333:"io_pgetevents", 334:"rseq", 335:"pkey_mprotect" }
for x in range(1000):
    if x not in syscalls:
        syscalls[x] = "???"

# Simple dataclass
@dataclass
class CallInfo():
    r14: int
    r15: int
    pid: int
    tid: int
    callno: int

    def __str__(self):
        return f"CallInfo(r14={self.r14:x}, r15={self.r15:x}, ptid=({self.pid}, {self.tid}), call {syscalls[self.callno]})"

register_data = {}  # unique, per syscall key -> CallInfo
active = {} # (pid, tid): [key, key]. Active syscalls for each thread - list may never have more than 2 elements or we'll assert because that seems wrong

# Init at a sort of unique value so we can eyeball it later
ctr_base = 0xd00d000
ctr = ctr_base

# How many syscalls had syscalls within syscalls?
waitc = 0

# If we just used PC, how often would we be wrong?
just_pc_wrong = 0
just_pc_keys = {} # pc of ret -> key

# If we used ASID as our UID, how often would we be wrong?
just_asid_wrong = 0
just_asid_keys = {} # asid -> key

# If we used both asid and PC how often would we be wrong?
just_asid_pc_wrong = 0
just_asid_pc_keys = {} # (asid, pc) -> key

def get_pid_tid(panda, cpu):
    current_proc = panda.plugins['osi'].get_current_process(cpu)
    assert(current_proc != panda.ffi.NULL)
    pid = current_proc.pid

    current_thread = panda.plugins['osi'].get_current_thread(cpu)
    assert(current_thread != panda.ffi.NULL)
    tid = current_thread.tid

    return (pid, tid)

if LOG_INSNS:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insn_cache = {} # address -> disassembly string

    def generate_insns(cpu, tb):
        # Disassemble each basic block and store in insn_cache
        asid = panda.current_asid(cpu)

        if asid not in insn_cache:
            insn_cache[asid] = {}

        if tb.pc in insn_cache[asid]:
            assert(len(insn_cache[asid][tb.pc]))
            return
        
        code = panda.virtual_memory_read(cpu, tb.pc, tb.size)

        insn_cache[asid][tb.pc] = ""

        cnt = 0
        for i in md.disasm(code, tb.pc):
            insn_cache[asid][tb.pc] += ("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))
            cnt += 1

        if cnt == 0 and len(code):
            print("FAILED TO DECODE:", code)
            del insn_cache[asid][tb.pc]

    #@panda.cb_after_block_translate
    def before_block_trans(cpu, tb):
        # Before we translate each block in find cache its disassembly
        generate_insns(cpu, tb)

    log_f = open("insns.txt", "w")
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

if not TAKE_RECORDING:
    @panda.ppp("syscalls2", "on_all_sys_enter")
    def on_syscall(cpu, pc, callno):
        #if callno == 15:
        #    # demagic r14 on sigreturn
        #    pid, tid = get_pid_tid(panda, cpu)
        #    print(f"SIGRETURN in {pid},{tid}")
        #    #panda.arch.set_reg(cpu, "R14", 0) # Hm, sigreturn is about to restore registers, so we shouldn't reallly care? - Without this we diverged?

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

        global ctr
        r14 = panda.arch.get_reg(cpu, "R14")
        r15 = panda.arch.get_reg(cpu, "R15")

        #asid = panda.current_asid(cpu)
        pid, tid = get_pid_tid(panda, cpu)

        key = ctr
        ctr += 1

        #print(f"\nPANDA CALL {syscalls[callno]} for {pid},{tid} at {pc:x}")

        # We can have two syscalls in flight at once, but more than that seems wrong
        if (pid, tid) in active and len(active[(pid, tid)]) == 1:
            print(f"INFO: We see {syscalls[callno]} while waiting on {len(active[(pid, tid)])} pending returns")
            global waitc
            waitc+=1

            for existing_key in active[(pid, tid)]:
                print(f"\t{existing_key:x} => {register_data[existing_key]}")

        if (pid, tid) in active and len(active[(pid, tid)]) > 1:
            print(f"\tFATAL: too many unret'd syscall in {pid},{tid}. Call to {syscalls[callno]} while waiting on return of:")
            for existing_key in active[(pid, tid)]:
                print(f"\t{existing_key:x} => {register_data[existing_key]}")
            print()
            raise RuntimeError("Active syscall already exists")

        if (pid, tid) not in active:
            active[(pid, tid)] = []
        
        active[(pid, tid)].append(key)
        register_data[key] = CallInfo(r14, r15, pid, tid, callno)

        panda.arch.set_reg(cpu, "R14", MAGIC_VALUE)
        panda.arch.set_reg(cpu, "R15", key)

        asid = panda.current_asid(cpu)
        just_pc_keys[pc+2] = key

        #print(f"Storing JPK of {pc+2:x} => {key:x}")
        just_asid_keys[asid] = key
        just_asid_pc_keys[(asid, pc+2)] = key

    # On sysret, restore R14, R15
    # XXX Panda's on_all_sy_return MISSES some returns - we'll use our explicit hooks instead and call this
    #@panda.ppp("syscalls2", "on_all_sys_return")
    def on_sysret(cpu, pc, panda_callno):
        r14 = panda.arch.get_reg(cpu, "R14")
        r15 = panda.arch.get_reg(cpu, "R15")
        #print(f"panda syseret {r14:x},{r15:x}")

        if r14 != MAGIC_VALUE:
            print("ignore")
            return

        #asid = panda.current_asid(cpu)
        retval = panda.arch.get_arg(cpu, 0, convention="syscall")
        pid, tid = get_pid_tid(panda, cpu)

        if (pid, tid) not in active:
            #print(f"\tRET {pid},{tid} ??=>{retval}")
            print(f"Warning: {pid},{tid} not in active on return: {r15:x} {retval}")
            raise RuntimeError("Double return?")

        # Drop key (r15) from active list for this pid,tid
        active[(pid, tid)].pop(active[(pid, tid)].index(r15))

        fail = None
        try:
            saved = register_data[r15]
            skip = r15 in just_pc_keys.values() or r15 in just_asid_keys.values() or r15 in just_asid_pc_keys.values()
            if not skip:
                # Don't delete if one of the bad techniques has a stale reference - we want to see it later to debug them
                del register_data[r15]
        except KeyError:
            fail = f"Key {r15:x} not found in register_data"

        if not fail:
            if pid != saved.pid:
                fail = f"PID changed from {saved.pid} to {pid}"

            if tid != saved.tid:
                fail = f"tid changed from {saved.tid} to {tid}"

        if fail is not None:
            raise RuntimeError(fail)

        panda.arch.set_reg(cpu, "R14", saved.r14)
        panda.arch.set_reg(cpu, "R15", saved.r15)

        global just_pc_wrong, just_asid_wrong, just_asid_pc_wrong
        if just_pc_keys[pc] != r15:
            if just_pc_keys[pc] in register_data:
                print(f"WRONG JPC: have {register_data[just_pc_keys[pc]]} want {saved}")
            else:
                print(f"WRONG JPC: have ??? (deleted) want {saved}")
            just_pc_wrong+=1

        asid = panda.current_asid(cpu)
        if just_asid_keys[asid] != r15:
            if just_asid_keys[asid] in register_data:
                print(f"WRONG ASID: have {register_data[just_asid_keys[asid]]} want {saved}")
            else:
                print(f"WRONG ASID: have ??? (deleted) want {saved}")
            just_asid_wrong+=1

        try:
            if just_asid_pc_keys[(asid, pc)] != r15:
                if just_asid_pc_keys[(asid, pc)] in register_data:
                    print(f"WRONG ASID+PC: have {register_data[just_asid_pc_keys[(asid, pc)]]} want {saved}")
                else:
                    print(f"WRONG ASID+PC: have ??? (deleted) want {saved}")
                just_asid_pc_wrong+=1
        except KeyError:
            print(f"WRONG ASID+PC: have ??? (no entry) want {saved}")
            just_asid_pc_wrong+=1

        #print(f"RET {pid},{tid}: {syscalls[saved.callno]}=>{retval}")

    # Manually identified address - it's where the syscall instruction jumps to (LSTAR?)
    @panda.hook(0xffffffff81a00020)
    def hook_syscall(cpu, tb, h):
        r14 = panda.arch.get_reg(cpu, "R14")
        r15 = panda.arch.get_reg(cpu, "R15")
        try:
            saved = register_data[r15]
            if r14 == MAGIC_VALUE:
                #print(f"SYSCALL {r14:x} {r15:x}: {saved}")
                pass
        except KeyError:
            #print(f"SYSCALL {r14:x} {r15:x}: ???")
            pass


    # Manually identified address - it's the block in the kernel that does the sysretq instruction
    @panda.hook(0xffffffff81a00152)
    def hook_sysret(cpu, tb, h):
        # This block is the syscall return
        r14 = panda.arch.get_reg(cpu, "R14")
        r15 = panda.arch.get_reg(cpu, "R15")
        try:
            saved = register_data[r15]
            if r14 == MAGIC_VALUE:
                #print(f"SYSRET: {r14:x} {r15:x}: {saved}")
                # We're on the sysretq block - we'll jump to RCX (which is the address of the instruction after the syscall)
                try:
                    on_sysret(cpu, panda.arch.get_reg(cpu, "RCX"), saved.callno)
                except Exception as e:
                    print("ON_SYSRET EXN:", e)
        except KeyError:
            #print(f"SYSRET: {r14:x} {r15:x}: ???")
            pass
    
    # We don't actually care about interrupts?
    '''
    @panda.cb_before_handle_interrupt
    def pre_interrupt(cpu, intno):
        pid, tid = get_pid_tid(panda, cpu)

        if (pid, tid) in active:
            procname = panda.get_process_name(cpu)
            print(f"INTERRUPTED SYSCALL IN {procname} ({pid},{tid})")
            print(f"\tPreviously was running syscall {register_data[active[(pid, tid)]]}")

        return intno
    '''

if TAKE_RECORDING:
    @panda.queue_blocking
    def driver():
        #panda.record_cmd("whoami", recording_name="whoami", snap_name="coreutils")

        # Need to add cflag, otherwise it won't build with the 18.04 installed compiler, even unmodified
        #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. VERBOSE=yes" # OOMs on my dev machine :(
        cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/tail-2/inotify-race VERBOSE=yes"

        panda.revert_sync("coreutils")

        panda.run_monitor_cmd("begin_record coreutils")
        out = panda.run_serial_cmd(cmd, timeout=60*100)
        panda.run_monitor_cmd("end_record")

        print(out)

        panda.end_analysis()

    panda.run()

else:
    panda.run_replay("coreutils")

    print(f"Of {ctr-ctr_base} syscalls, {waitc} were nested")

    print(f"Just PC wrong: {just_pc_wrong}")
    print(f"Just ASID wrong: {just_asid_wrong}")
    print(f"Just ASID+PC wrong: {just_asid_pc_wrong}")