#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
d=$(dirname "${BASH_SOURCE[0]}")
. $d/utils.sh

firmware_dir=${ci_root}/firmware

fw_rv32_opensbi=$(echo ${ci_fw_root}/firmware_rv32_opensbi_*.tar.zst)
fw_rv64_opensbi=$(echo ${ci_fw_root}/firmware_rv64_opensbi_*.tar.zst)
fw_rv64_uboot=$(echo ${ci_fw_root}/firmware_rv64_uboot_*.tar.zst)
fw_rv64_edk2=$(echo ${ci_fw_root}/firmware_rv64_edk2_*.tar.zst)

mkdir -p ${firmware_dir}/rv32
mkdir -p ${firmware_dir}/rv64

tar -C ${firmware_dir}/rv32 -xf $fw_rv32_opensbi
tar -C ${firmware_dir}/rv64 -xf $fw_rv64_opensbi
tar -C ${firmware_dir}/rv64 -xf $fw_rv64_uboot
tar -C ${firmware_dir}/rv64 -xf $fw_rv64_edk2
