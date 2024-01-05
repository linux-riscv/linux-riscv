#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

# Prepares a VM image, from a kernel tar-ball and a rootfs.

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

# e.g. super-duper-image.img
imagename=$1
# e.g. untarred linux_ubuntu_rv64_gcc_defconfig_plain.tar.xz
kernelpath=$2
# e.g rootfs_rv64_alpine_2023.03.13.tar.xz
rootfs=$3

tmp=$(mktemp -d -p "$PWD")

cleanup() {
    rm -rf "$tmp"

    if [[ -n ${tmpfile:-} ]]; then
        rm -rf "$tmpfile" || true
    fi
}
trap cleanup EXIT

unxz --keep --stdout $rootfs > $tmp/$(basename $rootfs .xz)

rootfs="$tmp/$(basename $rootfs .xz)"
modpath=$(find $kernelpath -wholename '*/lib/modules')
vmlinuz=$(find $kernelpath -name '*vmlinuz*')

rm -rf $imagename

imsz=1
if [[ -n $modpath ]]; then
    imsz=$(du -B 1G -s "$modpath" | awk '{print $1}')
fi

imsz=$(( ${imsz} + 1 ))

# Soft fallback to TCG is broken on aarch64, but forcing TCG works.
export LIBGUESTFS_BACKEND_SETTINGS=force_tcg
eval "$(guestfish --listen)"

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

# XXXXXXXXXXXXXXXXXX
# Add the tests here...
#
#
# XXXXXXXXXXXXXXXXXX

guestfish --remote -- \
          sync : \
          umount /boot/efi : \
          umount / : \
          exit
