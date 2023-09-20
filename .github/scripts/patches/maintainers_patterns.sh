#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#

tmpfile_b=$(mktemp)
tmpfile_n=$(mktemp)

rc=1

HEAD=$(git rev-parse HEAD)

git checkout -q HEAD~

./scripts/get_maintainer.pl --self-test=patterns > $tmpfile_b

before=$(cat $tmpfile_b | wc -l)

git checkout -q $HEAD

./scripts/get_maintainer.pl --self-test=patterns > $tmpfile_n

now=$(cat $tmpfile_n | wc -l)


if [ $now -gt $before ]; then
  echo "MAINTAINERS pattern errors before the patch: $before and now $now"
  echo "New pattern errors added, run ./scripts/get_maintainer.pl --self-test=patterns for more info" 1>&2
else
  rc=0
fi

rm -rf $tmpfile_b $tmpfile_n

exit $rc
