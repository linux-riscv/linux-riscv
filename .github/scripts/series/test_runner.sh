#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

kernels_dir=/build/kernels
rootfs_dir=/rootfs
log_dir=/build/tests

xlen=$1
config=$2
fragment=$3
toolchain=$4
rootfs=$5

lnx="${kernels_dir}/${xlen}_${toolchain}_${config//_/-}_$(basename $fragment)"
rootfs=$(echo ${rootfs_dir}/rootfs_${xlen}_${rootfs}_*.tar.xz)

mkdir -p /build/tests || true

echo "::group::Testing ${lnx} ${rootfs}"
rc=0
$d/run_test.sh "${lnx}" "${rootfs}" \
               > "${log_dir}/run_test_$(basename ${lnx})_$(basename ${rootfs} .tar.xz).log" \
               2>&1 || rc=$?
echo "::endgroup::"
if (( $rc )); then
    echo "::error::FAIL ${lnx} ${rootfs}"
else
    echo "::notice::OK ${lnx} ${rootfs}"
fi
