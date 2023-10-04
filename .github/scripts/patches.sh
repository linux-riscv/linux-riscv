#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

. ${d}/helpers.sh

basesha=$(git log -1 --pretty=%H .github/scripts/helpers.sh)
patches=( $(git rev-list --reverse ${basesha}..HEAD) )

rc=0
cnt=1
for i in "${patches[@]}"; do
    tests=( $(ls ${d}/patches/*.sh) )
    tcnt=1
    for j in "${tests[@]}"; do
        git reset --hard $i >/dev/null
        msg="Patch ${cnt}/${#patches[@]}: Test ${tcnt}/${#tests[@]}: ${j}"
        echo "::group::${msg}"
        testrc=0
        bash ${j} || testrc=$?
        echo "::endgroup::"
        if (( $testrc == 250 )); then
            rc=1
            echo "::warning::WARN ${msg}"
        elif (( $testrc )); then
            rc=1
            echo "::error::FAIL ${msg}"
        else
            echo "::notice::OK ${msg}"
        fi
        tcnt=$(( tcnt + 1 ))
    done
    cnt=$(( cnt + 1 ))
done

exit $rc
