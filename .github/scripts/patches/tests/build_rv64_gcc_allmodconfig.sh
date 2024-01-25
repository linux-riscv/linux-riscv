#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 Netronome Systems, Inc.

# Modified tests/patch/build_defconfig_warn.sh for RISC-V builds

tmpfile_e=$(mktemp -p /build)
tmpfile_o=$(mktemp -p /build)
tmpfile_n=$(mktemp -p /build)

tmpdir_b=build_gcc
tmpdir_o=output

rc=0

echo "Redirect to $tmpfile_o and $tmpfile_n"

HEAD=$(git rev-parse HEAD)

echo "Tree base:"
git log -1 --pretty='%h ("%s")' HEAD~

echo "Building the whole tree with the patch"

tuxmake --wrapper ccache --target-arch riscv -e PATH=$PATH --directory . \
        --environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
        --environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
        -o $tmpdir_o -b $tmpdir_b --toolchain gcc -z none --kconfig allmodconfig \
        -K CONFIG_WERROR=n -K CONFIG_GCC_PLUGINS=n W=1 \
        CROSS_COMPILE=riscv64-linux- \
        config default \
        >$tmpfile_e 2>/dev/null || rc=1

if [ $rc -eq 1 ]; then
        grep "\(error\):" $tmpfile_e
        rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b $tmpfile_e
        exit $rc
fi

git checkout -q HEAD~

echo "Building the tree before the patch"

tuxmake --wrapper ccache --target-arch riscv -e PATH=$PATH --directory . \
        --environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
        --environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
        -o $tmpdir_o -b $tmpdir_b --toolchain gcc -z none --kconfig allmodconfig \
        -K CONFIG_WERROR=n -K CONFIG_GCC_PLUGINS=n W=1 \
        CROSS_COMPILE=riscv64-linux- \
        config default \
        >$tmpfile_o 2>/dev/null

incumbent=$(grep -c "\(warning\|error\):" $tmpfile_o)

git checkout -q $HEAD

echo "Building the tree with the patch"

tuxmake --wrapper ccache --target-arch riscv -e PATH=$PATH --directory . \
        --environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
        --environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
        -o $tmpdir_o -b $tmpdir_b --toolchain gcc -z none --kconfig allmodconfig \
        -K CONFIG_WERROR=n -K CONFIG_GCC_PLUGINS=n W=1 \
        CROSS_COMPILE=riscv64-linux- \
        config default \
        >$tmpfile_n 2>/dev/null || rc=1

if [ $rc -eq 1 ]; then
        grep "\(warning\|error\):" $tmpfile_n
        rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b
        exit $rc
fi

current=$(grep -c "\(warning\|error\):" $tmpfile_n)

if [ $current -gt $incumbent ]; then
        echo "New errors added:"

        tmpfile_errors_before=$(mktemp -p /build)
        tmpfile_errors_now=$(mktemp -p /build)
        grep "\(warning\|error\):" $tmpfile_o | sort | uniq -c > $tmpfile_errors_before
        grep "\(warning\|error\):" $tmpfile_n | sort | uniq -c > $tmpfile_errors_now

        diff -U 0 $tmpfile_errors_before $tmpfile_errors_now

        rm $tmpfile_errors_before $tmpfile_errors_now

        echo "Per-file breakdown"
        tmpfile_fo=$(mktemp -p /build)
        tmpfile_fn=$(mktemp -p /build)

        grep "\(warning\|error\):" $tmpfile_o | sed -n 's@\(^\.\./[/a-zA-Z0-9_.-]*.[ch]\):.*@\1@p' | sort | uniq -c \
          > $tmpfile_fo
        grep "\(warning\|error\):" $tmpfile_n | sed -n 's@\(^\.\./[/a-zA-Z0-9_.-]*.[ch]\):.*@\1@p' | sort | uniq -c \
          > $tmpfile_fn

        diff -U 0 $tmpfile_fo $tmpfile_fn
        rm $tmpfile_fo $tmpfile_fn
        echo "pre: $incumbent post: $current"

        rc=1
fi

rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b $tmpfile_e

exit $rc
