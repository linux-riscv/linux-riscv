# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

# https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions

group_start() {
    echo "::group::$1"
}

group_end() {
    echo "::endgroup::"
}
