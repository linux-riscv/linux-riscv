#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2022 by Rivos Inc.

tmpdir=$(mktemp -d)
tmpfile=$(mktemp)
rc=0

tuxmake --wrapper ccache --target-arch riscv --directory . \
        --environment=KBUILD_BUILD_TIMESTAMP=@1621270510 \
        --environment=KBUILD_BUILD_USER=tuxmake --environment=KBUILD_BUILD_HOST=tuxmake \
        -o $tmpdir --toolchain gcc -z none -k nommu_k210_defconfig \
        CROSS_COMPILE=riscv64-linux- \
        > $tmpfile || rc=1

if [ $rc -ne 0 ]; then
  grep "\(warning\|error\):" $tmpfile >&2
fi

rm -rf $tmpdir $tmpfile

exit $rc
