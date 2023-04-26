#!/bin/bash
function finish {
  stty sane
}
trap finish EXIT
set -eux

# WORKS?
CAP=perf_eval
#CAP=envadder
#CAP=no_root_socks
#CAP=get_sysinfo
#CAP=ps
#CAP=test

#WIP 
#CAP=pwreset
#CAP=launchssh # It did take a bit when the guest was idle though
#CAP=is_paged_out
#CAP=secretfile
#CAP=readfile

# BROKEN? Maybe fixed now
#CAP=attest
#CAP=sbom
#CAP=2fa
#CAP=2fa_net

export N=1

# Rebuild qemu every time
make -C build -j$(nproc)

# Rebuild cap every time
make -C ../cap_libs progs/${CAP}.so
CAP="${HOME}/hhyde/cap_libs/progs/${CAP}.so"

QCOW=~/.panda/ubuntu-jammy.qcow
#QCOW=~/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2

HYDE_ENABLE="-hyde-enable $CAP"

CORES="-smp 8,sockets=2,cores=4"
#LOADVM=eightcore
#LOADVM=eightcoreroot
LOADVM=eightstrace

#CORES=""
#LOADVM="gdb2" # Singlecore

#VALGRIND=valgrind -- log-file=log.txt --track-origins=yes --error-limit=no
VALGRIND=""

#GDB="gdb --args"
GDB=""

${VALGRIND} ${GDB} ./build/qemu-system-x86_64 -m 1G -accel kvm ${CORES} "${QCOW}" -nographic -loadvm $LOADVM ${HYDE_ENABLE}
