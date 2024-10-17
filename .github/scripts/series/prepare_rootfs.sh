#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

# Prepares a VM image, from a kernel tar-ball and a rootfs.

set -x
set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")
. $d/utils.sh
. $d/qemu_test_utils.sh

kernelpath=$1
rootfs=$2
tst=$3
imagename=$4

cleanup() {
    rm -rf "$tmp"
}

tmp=$(mktemp -d -p ${ci_root})
trap cleanup EXIT

unzstd --keep --stdout $rootfs > $tmp/$(basename $rootfs .zst)

rootfs="$tmp/$(basename $rootfs .zst)"
modpath=$(find $kernelpath -wholename '*/lib/modules')
vmlinuz=$(find $kernelpath -name '*vmlinuz*')

kselftestpath=${kernelpath}_build/kselftest

imsz=0
if [[ $tst =~ kselftest ]]; then
    sz=$(du -B 1G -s "$kselftestpath" | awk '{print $1}')
    imsz=$(( ${imsz} + $sz ))
fi

if [[ -n $modpath ]]; then
    sz=$(du -B 1G -s "$modpath" | awk '{print $1}')
    imsz=$(( ${imsz} + $sz ))
fi
imsz=$(( ${imsz} + 2 ))

# aarch64 export LIBGUESTFS_BACKEND_SETTINGS=force_tcg
export LIBGUESTFS_BACKEND_SETTINGS=force_kvm
eval "$(guestfish --listen)"

rm -rf $imagename
guestfish --remote -- \
          disk-create "$imagename" raw ${imsz}G : \
          add-drive "$imagename" format:raw : \
          launch : \
          part-init /dev/sda gpt : \
          part-add /dev/sda primary 2048 526336 : \
          part-add /dev/sda primary 526337 -34 : \
          part-set-gpt-type /dev/sda 1 C12A7328-F81F-11D2-BA4B-00A0C93EC93B : \
          mkfs ext4 /dev/sda2 : \
          mount /dev/sda2 / : \
          mkdir /boot : \
          mkdir /boot/efi : \
          mkfs vfat /dev/sda1 : \
          mount /dev/sda1 /boot/efi : \
          tar-in $rootfs / : \
          copy-in $vmlinuz /boot/efi/ : \
          mv /boot/efi/$(basename $vmlinuz) /boot/efi/Image


if [[ -n $modpath ]]; then
    guestfish --remote -- copy-in $modpath /lib/
fi

if [[ $tst =~ kselftest ]]; then
    guestfish --remote -- \
              copy-in $kselftestpath /

    touch $tmp/dotest
    chmod +x $tmp/dotest
    cat >$tmp/dotest <<EOF
#!/bin/bash

set -x
echo "<5>Hello kselftest" > /dev/kmsg
cd /kselftest
export PATH=${PATH}:/kselftest/bpf/tools/sbin

EOF
    case ${tst} in
        "kselftest-ftrace")
            cat >>$tmp/dotest <<EOF
echo "TEST ftrace"
./run_kselftest.sh -o 3600 -c ftrace
EOF
            ;;
        "kselftest-net")
            cat >>$tmp/dotest <<EOF
echo "TEST net"
./run_kselftest.sh -o 3600 -c net
EOF
            ;;
        "kselftest-bpf")
            cat >>$tmp/dotest <<EOF
echo "TEST bpf"
./run_kselftest.sh -o 9000 -c bpf
EOF
            ;;
        *)
            cat >>$tmp/dotest <<EOF
for i in \$(./run_kselftest.sh -l | egrep '^[/a-z0-9]+:' | awk -F: '{print \$1}' |uniq |egrep -v 'bpf|net|ftrace|lkdtm|breakpoints'); do
    echo "TEST  \$i"
    ./run_kselftest.sh -o 3600 -c \$i
done
EOF
            ;;
    esac

    echo "dotest:"
    cat $tmp/dotest
    echo "dotest end"
    guestfish --remote -- \
              copy-in $tmp/dotest /
fi

guestfish --remote -- \
          sync : \
          umount /boot/efi : \
          umount / : \
          exit
