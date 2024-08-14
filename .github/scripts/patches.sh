#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

parallel_log=$(mktemp -p /build)
basesha=$(git log -1 --pretty=%H .github/scripts/patches.sh)
patches=( $(git rev-list --reverse ${basesha}..HEAD) )

echo "git-tip begin"
git log -1 $(git log -1 --pretty=%H .github/scripts/patches.sh)^
echo "git-tip end"

patch_tot=${#patches[@]}
rc=0
cnt=1

# Linear
for i in "${patches[@]}"; do
    time bash ${d}/patches/patch_tester.sh ${i} ${cnt} ${patch_tot} || rc=1
    cnt=$(( cnt + 1 ))
done
exit 0

# Parallel... (slower?)
parallel -j 4 --joblog ${parallel_log} --colsep=, bash ${d}/patches/patch_tester.sh \
	 {1} {2} {3} :::: <(
    for i in "${patches[@]}"; do
        echo ${i},${cnt},${patch_tot}
        cnt=$(( cnt + 1 ))
    done) || rc=1
cat ${parallel_log}

