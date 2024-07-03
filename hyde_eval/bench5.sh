#!/bin/bash

QEMU_PATH=../build/qemu-system-x86_64
QEMU_IMG_PATH=~/jammy.qcow
LOADVM=lmbench2

export N=1000
CAP=perf_eval
CAP="${HOME}/hhyde/cap_libs/progs/${CAP}.so"

QEMU_ARGS="${QEMU_PATH} -m 1G -accel kvm ${QEMU_IMG_PATH} -nographic -loadvm $LOADVM -hyde-enable \"$CAP\""

GUEST_COMMAND="cd ~/coreutils.rw; time make check SUBDIRS=."

for i in {1..5}; do
    ./bench1.sh "${QEMU_ARGS}" "${GUEST_COMMAND}"
done
