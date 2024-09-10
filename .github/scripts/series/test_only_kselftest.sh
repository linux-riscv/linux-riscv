#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")
. $d/utils.sh
. $d/kselftest_prep.sh

$d/unpack_fw.sh
${d}/kernel_tester.sh rv64 kselftest plain gcc ubuntu || rc=1
exit $rc
