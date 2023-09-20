#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 Netronome Systems, Inc.

# Modified tests/patch/build_defconfig_warn.sh for RISC-V builds

tmpfile_e=$(mktemp)
tmpfile_o=$(mktemp)
tmpfile_n=$(mktemp)

tmpdir_b=build_llvm
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
	-o $tmpdir_o -b $tmpdir_b --toolchain llvm -z none --kconfig allmodconfig \
	-K CONFIG_WERROR=n -K CONFIG_RANDSTRUCT_NONE=y -K CONFIG_SAMPLES=n W=1 \
	CROSS_COMPILE=riscv64-linux- \
	config default \
	> $tmpfile_e || rc=1

if [ $rc -eq 1 ]
then
	grep "\(error\):" $tmpfile_e >&2
	rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b $tmpfile_e
	exit $rc
fi

current=$(grep -c "\(warning\|error\):" $tmpfile_n)

git checkout -q HEAD~

echo "Building the tree before the patch"

tuxmake --wrapper ccache --target-arch riscv -e PATH=$PATH --directory . \
	--environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
	--environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
	-o $tmpdir_o -b $tmpdir_b --toolchain llvm -z none --kconfig allmodconfig \
	-K CONFIG_WERROR=n -K CONFIG_RANDSTRUCT_NONE=y W=1 \
	CROSS_COMPILE=riscv64-linux- \
	config default \
	> $tmpfile_o

incumbent=$(grep -c "\(warning\|error\):" $tmpfile_o)

git checkout -q $HEAD

echo "Building the tree with the patch"

tuxmake --wrapper ccache --target-arch riscv -e PATH=$PATH --directory . \
	--environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
	--environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
	-o $tmpdir_o -b $tmpdir_b --toolchain llvm -z none --kconfig allmodconfig \
	-K CONFIG_WERROR=n -K CONFIG_RANDSTRUCT_NONE=y W=1 \
	CROSS_COMPILE=riscv64-linux- \
	config default \
	> $tmpfile_n || rc=1

if [ $rc -eq 1 ]
then
	grep "\(warning\|error\):" $tmpfile_n >&2
	rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b
	exit $rc
fi

current=$(grep -c "\(warning\|error\):" $tmpfile_n)

if [ $current -gt $incumbent ]; then
  echo "New errors added:" 1>&2

  tmpfile_errors_before=$(mktemp)
  tmpfile_errors_now=$(mktemp)
  grep "\(warning\|error\):" $tmpfile_o | sort | uniq -c > $tmpfile_errors_before
  grep "\(warning\|error\):" $tmpfile_n | sort | uniq -c > $tmpfile_errors_now

  diff -U 0 $tmpfile_errors_before $tmpfile_errors_now 1>&2

  rm $tmpfile_errors_before $tmpfile_errors_now

  echo "Per-file breakdown" 1>&2
  tmpfile_fo=$(mktemp)
  tmpfile_fn=$(mktemp)

  grep "\(warning\|error\):" $tmpfile_o | sed -n 's@\(^\.\./[/a-zA-Z0-9_.-]*.[ch]\):.*@\1@p' | sort | uniq -c \
    > $tmpfile_fo
  grep "\(warning\|error\):" $tmpfile_n | sed -n 's@\(^\.\./[/a-zA-Z0-9_.-]*.[ch]\):.*@\1@p' | sort | uniq -c \
    > $tmpfile_fn

  diff -U 0 $tmpfile_fo $tmpfile_fn 1>&2
  rm $tmpfile_fo $tmpfile_fn
  echo "pre: $incumbent post: $current"
  rc=1
fi

rm -rf $tmpdir_o $tmpfile_o $tmpfile_n $tmpdir_b $tmpfile_e

exit $rc
