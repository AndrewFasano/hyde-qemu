#!/bin/bash
function finish {
  stty sane
}
trap finish EXIT

set -eu

# All work for Ubuntu 22.04 + 18.04
#CAP=perf_eval
#CAP=envadder
#CAP=no_root_socks
#CAP=get_sysinfo
#CAP=ps
#CAP=file_access_log
#CAP=secretfile
#CAP=2fa      # Some issues on 18.04, might also be present on 22.04
#CAP=2fa_net
#CAP=pwreset
#CAP=sbom
#CAP=attest # Not yet tested on 18.04

#WIP 
#CAP=launchssh # Needs support for injecting through forks

export N=5

# Rebuild qemu every time
make -C build -j$(nproc)

# Rebuild cap every time
make -C ../cap_libs progs/${CAP}.so
CAP="${HOME}/hhyde/cap_libs/progs/${CAP}.so"

#QCOW=~/.panda/ubuntu-jammy.qcow
QCOW=~/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2
#QCOW=~/hhyde/qcows/FreeBSD-12.1-RELEASE-amd64.qcow2

HYDE_ENABLE="-hyde-enable $CAP"
#HYDE_ENABLE=""

CORES="-smp 8,sockets=2,cores=4"
#LOADVM=eightcore # This is like 521-522 passing
LOADVM=eightcoreroot # jammy and bionic and bsd - Maybe goal is 489 tests pass 152 skip
#LOADVM=eightstrace

#CORES=""
#LOADVM="gdb2" # Singlecore - jammy

LOAD="-loadvm ${LOADVM}"
#LOAD=""

#VALGRIND="valgrind --log-file=log.txt --track-origins=yes --error-limit=no"
VALGRIND=""

#GDB="gdb --args"
GDB=""

echo -e "\n\nRUNNING ${VALGRIND} ${GDB}\n\t${QCOW} ${CORES} ${LOADVM}:\n\t${HYDE_ENABLE}\n\n"

${VALGRIND} ${GDB} ./build/qemu-system-x86_64 -m 1G -accel kvm ${CORES} "${QCOW}" -nographic ${LOAD} ${HYDE_ENABLE}
