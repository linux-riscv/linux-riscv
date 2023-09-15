#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")

. ${d}/helpers.sh

group_start "Series"
tcnt=1
tests=( $(ls ${d}/series/*.sh) )
for i in "${tests[@]}"; do
    git reset --hard $i
    msg="Test ${tcnt}/${#tests[@]}: ${i}"
    echo "::group::${msg} @ $(date --utc +%Y-%m-%dT%H:%M:%S.%NZ)"
    bash ${i} "${msg}" || true
    echo "Completed $(date --utc +%Y-%m-%dT%H:%M:%S.%NZ)"
    echo "::endgroup::"
    tcnt=$(( tcnt + 1 ))
done
group_end
