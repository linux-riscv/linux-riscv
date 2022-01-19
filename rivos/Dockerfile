# Copyright (c) 2021 by Rivos Inc.
# Licensed under the GPL version 2, see LICENSES/preferred/GPL-2.0 for details.
# SPDX-License-Identifier: GPL-2.0
FROM gitlab.ba.rivosinc.com:5050/ext/sw/riscv-gnu-toolchain:latest as linux_builder

# Don't let debs run any interactive configuration scripts.
ARG DEBIAN_FRONTEND=noninteractive

# Install build deps for the Linux kernel.
RUN apt-get update && \
    apt-get -y -qq install autoconf \
                           bc \
                           bison \
                           dkms \
                           gawk \
                           flex \
                           libelf-dev \
                           libiberty-dev \
                           libncurses-dev \
                           libpci-dev \
                           libudev-dev \
                           openssl

COPY . /src/

# Limit parallelism on Gitlab runners to avoid exhausting memory.
ARG PARALLEL_JOBS

# For now, build only a monolithic kernel for our VM
# and a rudimentary install
RUN make -C /src ARCH=riscv \
         CROSS_COMPILE=riscv64-unknown-linux-gnu- \
         O=/rivos/linux defconfig && \
    make -C /src ARCH=riscv \
         CROSS_COMPILE=riscv64-unknown-linux-gnu- \
         O=/rivos/linux \
         Image -j ${PARALLEL_JOBS} && \
    mkdir -p /rivos/sysroot/riscv/boot && \
    make -C /src ARCH=riscv \
         CROSS_COMPILE=riscv64-unknown-linux-gnu- \
         O=/rivos/linux \
         INSTALL_PATH=/rivos/sysroot/riscv/boot \
         install

### Stage 2: Create a .deb Ubuntu package
FROM gitlab.ba.rivosinc.com:5050/rv/it/rivos-sdk/packager:latest as linux_packager

COPY --from=linux_builder /rivos/sysroot/riscv/boot /rivos/sysroot/riscv/boot

ARG UPVER
ARG PKGVER
ARG CI_JOB_TOKEN
ARG CI_PROJECT_NAME
ARG CI_PROJECT_URL
ARG SECTION

RUN ./build_upload_package --deb \
  --arch all \
  ${SECTION:+--component ${SECTION}} \
  --description "Linux kernel image for RISCV64." \
  --directory "/rivos/sysroot/riscv/boot" \
  --license "GPL-2.0" \
  --name "${CI_PROJECT_NAME}" \
  --pkg_version "${PKGVER}" \
  --token "${CI_JOB_TOKEN}" \
  --url "${CI_PROJECT_URL}" \
  --upstream_version "${UPVER}"

### Stage 3: create a fresh container image with the built artifacts
FROM ubuntu:20.04 as linux-kernel
COPY --from=linux_builder /rivos/sysroot/riscv/boot /rivos/sysroot/riscv/boot
COPY --from=linux_builder /rivos/linux /rivos/linux
