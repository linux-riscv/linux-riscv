#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

log_dir=/build/kernels/logs

mkdir -p "${log_dir}" || true

(while true ; do sleep 30; echo .; done) &
progress=$!

parallel_log=$(mktemp -p /build)
parallel -j 2 --colsep ' ' --joblog ${parallel_log} \
         ${d}/kernel_builder.sh {1} {2} {3} {4} :::: <($d/generate_build_configs.sh) || true
kill $progress
cat ${parallel_log}

