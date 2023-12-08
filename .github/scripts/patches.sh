#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

. ${d}/helpers.sh

basesha=$(git log -1 --pretty=%H .github/scripts/helpers.sh)
patches=( $(git rev-list --reverse ${basesha}..HEAD) )
patch_tot=${#patches[@]}
rc=0
cnt=1
parallel -j 3 --colsep=, bash ${d}/patch_tester.sh {1} {2} {3} :::: <(
    for i in "${patches[@]}"; do
	echo ${i},${cnt},${patch_tot}
	cnt=$(( cnt + 1 ))
    done) || rc=1

exit $rc
