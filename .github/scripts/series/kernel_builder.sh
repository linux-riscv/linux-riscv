#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

build_dir=$(mktemp -d -p /build)
install_dir=/build/kernels
log_dir=/build/kernels/logs

xlen=$1
config=$2
fragment=$3
toolchain=$4

n="${xlen}_${toolchain}_${config//_/-}_$(basename $fragment)"

echo "::group::Building linux_${n}"
rc=0
$d/build_kernel.sh "${xlen}" "${config}" "${fragment}" "${toolchain}" \
                   "${build_dir}" "${install_dir}" \
                   > "${log_dir}/build_kernel_${n}.log" 2>&1 || rc=$?
rm -rf ${build_dir}
echo "::endgroup::"
if (( $rc )); then
    echo "::error::FAIL linux_${n}"
else
    echo "::notice::OK linux_${n}"
fi
