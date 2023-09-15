#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2020 Facebook

inlines=$(
    git show -- '*.h' | grep -C1 -P '^\+static (?!(__always_)?inline).*\(';
    git show -- '*.h' | grep -C1 -P '^\+(static )?(?!(__always_)?inline )((unsigned|long|short) )*(char|bool|void|int|u[0-9]*) [0-9A-Za-z_]*\(.*\) *{'
       )

if [ -z "$inlines" ]; then
  echo "::notice::OK PATCH: $1"
  exit 0
else
  echo "::error::FAIL PATCH: $1"
  msg="Detected static functions without inline keyword in header files:"
  echo -e "$msg\n$inlines" 1>&2
  count=$( (echo "---"; echo "$inlines") | grep '^---$' | wc -l)
  echo "$msg $count"
  exit 1
fi
