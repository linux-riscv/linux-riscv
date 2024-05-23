#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -x
set -euo pipefail

d=$(dirname "${BASH_SOURCE[0]}")
lnxroot=$(pwd)

xlen=$1
config=$2
fragment=$3
toolchain=$4
output=$5
install=$6

triple=riscv64-linux-

make_gcc() {
    make LOCALVERSION=$local_version O=$output ARCH=riscv CROSS_COMPILE=$triple \
         "CC=ccache ${triple}gcc" 'HOSTCC=ccache gcc' $*
}

make_llvm() {
    make LOCALVERSION=$local_version O=$output ARCH=riscv CROSS_COMPILE=$triple \
         LLVM=1 LLVM_IAS=1 'CC=ccache clang' 'HOSTCC=ccache clang' $*
}

make_wrap() {
    if [ $toolchain == "llvm" ]; then
        make_llvm $*
    else
        make_gcc $*
    fi
}

local_version="-${config//_/-}_$(basename $fragment)"
name="${xlen}_${toolchain}_${config//_/-}_$(basename $fragment)"

rm -rf ${output}
mkdir -p ${output}
mkdir -p "${install}/${name}"

if [[ $config == "allmodconfig" || $config == "randconfig" ]]; then
    make_wrap KCONFIG_ALLCONFIG=$lnxroot/arch/riscv/configs/${xlen//rv/}-bit.config $config
    $lnxroot/scripts/kconfig/merge_config.sh -m -O $output $output/.config \
                                             <(echo "CONFIG_WERROR=n") \
                                             <(echo "CONFIG_GCC_PLUGINS=n")
elif [[ $config == "kselftest" ]]; then
    make_wrap defconfig
    make_wrap kselftest-merge
else
    if [[ $fragment == "plain" ]]; then
        $lnxroot/scripts/kconfig/merge_config.sh -m -O $output $lnxroot/arch/riscv/configs/$config \
                                                 $lnxroot/arch/riscv/configs/${xlen//rv/}-bit.config
    else
        $lnxroot/scripts/kconfig/merge_config.sh -m -O $output $lnxroot/arch/riscv/configs/$config \
                                                 $fragment \
                                                 $lnxroot/arch/riscv/configs/${xlen//rv/}-bit.config
    fi

    make_wrap olddefconfig
fi

make_wrap -j $(nproc) -Oline

mkdir -p "${install}/${name}" || true
make_wrap INSTALL_PATH="${install}/${name}" install
make_wrap INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH="${install}/${name}" modules_install || true

cp $output/vmlinux ${install}/${name}

# pushd ${install}
# tar -c -I 'xz -9 -T0' -f linux_${name}.tar.xz \
#    "${name}"
