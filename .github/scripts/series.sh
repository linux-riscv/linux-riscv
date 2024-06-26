#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

echo "git-tip begin"
git log -1 $(git log -1 --pretty=%H .github/scripts/patches.sh)^
echo "git-tip end"

${d}/series/build_kernels.sh
${d}/series/run_tests.sh
