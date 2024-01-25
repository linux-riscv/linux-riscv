#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

firmware_dir=/build/firmware

fw_rv32_opensbi=$(echo /firmware/firmware_rv32_opensbi_*.tar.xz)
fw_rv64_opensbi=$(echo /firmware/firmware_rv64_opensbi_*.tar.xz)
fw_rv64_uboot=$(echo /firmware/firmware_rv64_uboot_*.tar.xz)
fw_rv64_edk2=$(echo /firmware/firmware_rv64_edk2_*.tar.xz)

mkdir -p ${firmware_dir}/rv32
mkdir -p ${firmware_dir}/rv64

tar -C ${firmware_dir}/rv32 -xf $fw_rv32_opensbi

tar -C ${firmware_dir}/rv64 -xf $fw_rv64_opensbi
tar -C ${firmware_dir}/rv64 -xf $fw_rv64_uboot
tar -C ${firmware_dir}/rv64 -xf $fw_rv64_edk2
