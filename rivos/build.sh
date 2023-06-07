#!/bin/bash

set -e

COMPILE="riscv64-unknown-linux-gnu-"
CC="sccache riscv64-unknown-linux-gnu-gcc"

# For now, build only a monolithic kernel for our VM
# and a rudimentary install
kernel_build() {
    local config=$1
    local config_base=$2
    local config_to_merge=$3
    local local_version

    # Replace _ with - as _ is not valid in Debian versions
    local_version="${config//_/-}"

    make LOCALVERSION=$local_version ARCH=riscv CC="${CC}" CROSS_COMPILE="${COMPILE}" O=build_${config} ${config_base}

    if [ ! -z "$config_to_merge" ]; then
        # Avoid a mrproper by stepping into the directory
        cd build_${config}
        ARCH=riscv CC="${CC}" CROSS_COMPILE="${COMPILE}" ../scripts/kconfig/merge_config.sh .config ../$config_to_merge
        cd ..
    fi

    time make LOCALVERSION=$local_version ARCH=riscv CC="${CC}" CROSS_COMPILE="${COMPILE}" O=build_${config} -j $(nproc)

    # Prepare installation for packaging
    mkdir -p "${INSTALL_PATH}/${config}"

    # Compile and install the kernel (for legacy)
    time make LOCALVERSION=${local_version} ARCH=riscv CC="${CC}" CROSS_COMPILE="${COMPILE}" O=build_${config} INSTALL_PATH="${INSTALL_PATH}/${config}" install

    # Create the debian package with kernel + modules
    # INSTALL_MOD_STRIP will fix the module size issue caused by relocations
    # https://github.com/riscv-collab/riscv-gnu-toolchain/issues/1036
    time make LOCALVERSION=${local_version} ARCH=riscv CC="${CC}" CROSS_COMPILE="${COMPILE}" INSTALL_MOD_STRIP=1 O=build_${config} bindeb-pkg

    # FIXME dirty
    rm -f linux-image*dbg*.deb
    cp linux-image*${local_version}*.deb ${INSTALL_PATH}/${config}

    # For debugging purposes
    cp build_${config}/vmlinux ${INSTALL_PATH}/${config}
    cp build_${config}/arch/riscv/boot/Image ${INSTALL_PATH}/${config}
}

kernel_tar() {
    tar czf linux_$1.tar.gz "${INSTALL_PATH}"
}

if [ $# -lt 2 ]; then
	echo "Please provide at least one config name (\$1) and one base config (\$2)"
	exit -1
fi

if [ -z ${INSTALL_PATH} ]; then
    echo "Please provide INSTALL_PATH"
    exit -1
fi
rm -rf ${INSTALL_PATH}/*

kernel_build "$@"
kernel_tar $1
