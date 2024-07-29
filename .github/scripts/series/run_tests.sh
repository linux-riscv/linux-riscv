#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

$d/prepare_tests.sh

parallel_log=$(mktemp -p /build)
parallel -j $(($(nproc)-1)) --colsep ' ' --joblog ${parallel_log} \
         ${d}/test_runner.sh {1} {2} {3} {4} {5} :::: <($d/generate_test_runs.sh) || true
cat ${parallel_log}
