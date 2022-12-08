#!/bin/bash

# For now, build only a monolithic kernel for our VM
# and a rudimentary install
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- O=build defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- O=build Image -j $(nproc)
# Prepare installation for packaging
rm -rf "${INSTALL_PATH}"
mkdir -p "${INSTALL_PATH}"
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- O=build INSTALL_PATH="${INSTALL_PATH}" install
tar czf linux.tar.gz "${INSTALL_PATH}"

