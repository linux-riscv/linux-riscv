#!/bin/bash

set -e

sudo bash -c "echo -1 > /proc/sys/kernel/perf_event_paranoid"

# 1. User access by default
echo "*** User access"
sudo bash -c "echo 1 > /proc/sys/kernel/perf_user_access"
LD_LIBRARY_PATH=/opt/sources/linux/tools/lib/perf/ ./test_perf_mmap

# 2. No user access
echo "*** No user access"
sudo bash -c "echo 0 > /proc/sys/kernel/perf_user_access"
LD_LIBRARY_PATH=/opt/sources/linux/tools/lib/perf/ ./test_perf_mmap

# 3. Legacy mode
echo "*** Legacy"
sudo bash -c "echo 2 > /proc/sys/kernel/perf_user_access"
LD_LIBRARY_PATH=/opt/sources/linux/tools/lib/perf/ ./test_perf_mmap

