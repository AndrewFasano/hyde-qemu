from pandare import Panda

# We don't have an OSI profile for jammy :(
#panda = Panda("x86_64", mem="1G", expect_prompt=rb"ubuntu@ubuntu:~/.*\$", qcow="/home/andrew/.panda/ubuntu-jammy.qcow", ...)

# So I set up a panda 18.04 qcow with coreutils and dependencies pre-installed (setup with kvm, then snapped with panda as "coreutils")
# It's on 18.4.85.108:~andrew/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow
# This script runs the tests in it while doing our r14/r15 magic with syscalls2 and using OSI to track pid/tid at the same time
panda = Panda(generic="x86_64")

# Should have /root/coreutils ready to go? Justneed to snap

panda.load_plugin("osi")
panda.load_plugin("syscalls2", {"load-info": False})

MAGIC_VALUE = 0xdeadbeef

# Unique value mapping syscall -> details
register_data = {}  # (orig_r14, orig_r15, pid, tid, callno)
results = {} # (pid, tid): {key: (callno, retno)}


ctr = 0xd00d000

def get_pid_tid(panda, cpu):
    current_proc = panda.plugins['osi'].get_current_process(cpu)
    assert(current_proc != panda.ffi.NULL)
    pid = current_proc.pid

    current_thread = panda.plugins['osi'].get_current_thread(cpu)
    assert(current_thread != panda.ffi.NULL)
    tid = current_thread.tid

    return (pid, tid)

# Before every syscall
@panda.ppp("syscalls2", "on_all_sys_enter2")
def on_syscall(cpu, pc, call, rp):
    callno = panda.arch.get_arg(cpu, 0, convention="syscall")

    if callno in [  
                     15, # sigreturn

                     56, # clone
                     435, # clone3

                     57, # fork
                     58, # vfork

                     # noreturn:
                     59, # execve
                     60, # exit
                     231, #exit_group
                     322, # execveat
                    ]:
        return

    global ctr
    asid = panda.current_asid(cpu)

    r14 = panda.arch.get_reg(cpu, "R14")
    r15 = panda.arch.get_reg(cpu, "R15")

    pid, tid = get_pid_tid(panda, cpu)

    key = ctr
    ctr+=1

    register_data[key] = (r14, r15, pid, tid, callno)

    panda.arch.set_reg(cpu, "R14", MAGIC_VALUE)
    panda.arch.set_reg(cpu, "R15", key)

    #print(f"Syscall {callno} gets magic {key} pointing to {register_data[key]}")

# On sysret, restore R14, R15
@panda.ppp("syscalls2", "on_all_sys_return2")
def on_sysret(cpu, pc, call, rp):
    r14 = panda.arch.get_reg(cpu, "R14")

    if r14 != MAGIC_VALUE:
        return

    asid = panda.current_asid(cpu)
    retval = panda.arch.get_arg(cpu, 0, convention="syscall")
    r15 = panda.arch.get_reg(cpu, "R15")

    pid, tid = get_pid_tid(panda, cpu)

    fail = None
    try:
        orig_r14, orig_r15, orig_pid, orig_tid, callno = register_data[r15]
        del register_data[r15]
    except KeyError:
        fail = f"Key {r15:x} not found in register_data"
        
    if not fail:
        if pid != orig_pid:
            fail = f"PID changed from {orig_pid} to {pid}"

        if tid != orig_tid:
            fail = f"tid changed from {orig_tid} to {tid}"

    if fail is not None:
        print(f"On return from {callno} in {pid},{tid} (asid {asid:x}))")
        raise RuntimeError(fail)

    if (pid, tid) not in results:
        results[(pid, tid)] = {}
    results[(pid, tid)][r15] = (callno, retval)

    panda.arch.set_reg(cpu, "R14", orig_r14)
    panda.arch.set_reg(cpu, "R15", orig_r15)

    print(f"{pid},{tid}: {callno}=>{retval}")


@panda.queue_blocking
def driver():
    panda.revert_sync("coreutils")

    # Need to add cflag, otherwise it won't build with the 18.04 installed compiler, even unmodified
    #cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBIDRS=."
    cmd = "make check CFLAGS='-Wno-error=suggest-attribute=const -Wno-error=type-limits' SUBDIRS=. TESTS=tests/tail-2/inotify-race VERBOSE=yes"

    out = panda.run_serial_cmd(cmd, timeout=12000)
    with open("out.txt", "w") as f:
        f.write(out)
    print(out)
    panda.end_analysis()

panda.run()


#results = {} # (pid, tid): {key: (callno, retno)}

with open("results.txt", "w") as f:
    for ((pid, tid), d) in results.items():
        f.write(f"{pid},{tid}:\n")
        for (key, (callno, retval)) in d.items():
            f.write(f"  {key:x}: {callno}=>{retval}\n")
        f.write("\n")