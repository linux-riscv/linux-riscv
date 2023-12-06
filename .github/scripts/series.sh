#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

. ${d}/helpers.sh

rc=0
tcnt=1
tests=( $(ls ${d}/series/*.sh) )
for i in "${tests[@]}"; do
    git reset --hard HEAD >/dev/null
    msg="Test ${tcnt}/${#tests[@]}: ${i}"
    echo "::group::${msg}"
    testrc=0
    bash ${i} || testrc=1
    echo "::endgroup::"
    if (( $testrc )); then
        rc=1
        echo "::error::FAIL ${msg}"
    else
        echo "::notice::OK ${msg}"
    fi
    tcnt=$(( tcnt + 1 ))
done

exit $rc
