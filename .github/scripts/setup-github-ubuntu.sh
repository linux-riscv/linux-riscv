#!/bin/bash
# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

arch=$(uname -m)
case ${arch} in

  "x86_64")
    debarch="amd64"
    ;;

  "aarch64")
    debarch="arm64"
    ;;
esac


apt-get update && apt-get install --yes --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg

# Add additional packages here.
apt-get update && apt-get install --yes --no-install-recommends \
    arch-test \
    autoconf \
    automake \
    autotools-dev \
    bash-completion \
    bc \
    binfmt-support \
    bison \
    bsdmainutils \
    build-essential \
    cpio \
    curl \
    diffstat \
    flex \
    g++-riscv64-linux-gnu \
    gawk \
    gcc-riscv64-linux-gnu \
    gdb \
    gettext \
    git \
    git-lfs \
    gperf \
    groff \
    less \
    libelf-dev \
    liburing-dev \
    lsb-release \
    mmdebstrap \
    ninja-build \
    patchutils \
    perl \
    pkg-config \
    psmisc \
    python-is-python3 \
    python3-venv \
    qemu-user-static \
    rsync \
    ruby \
    ssh \
    strace \
    texinfo \
    traceroute \
    unzip \
    vim \
    zlib1g-dev \
    lsb-release \
    wget \
    software-properties-common \
    gnupg \
    cmake \
    libdw-dev \
    libssl-dev \
    python3-docutils \
    kmod \
    swig \
    python3-dev \
    ccache \
    pipx

echo "deb [arch=${debarch}] http://apt.llvm.org/jammy/ llvm-toolchain-jammy main" >> /etc/apt/sources.list.d/llvm.list

# wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
cat <<EOF > /etc/apt/trusted.gpg.d/apt.llvm.org.asc
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

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
bXb5c6gCHESH5PXwPU4jQEE7Ib9J6sbk7ZT2Mw==
=j+4q
-----END PGP PUBLIC KEY BLOCK-----
EOF

apt-get update
if [[ $debarch == "arm64" ]]; then
    apt-get install --yes clang-18 llvm-18 lld-18
else
    apt-get install --yes clang llvm lld
fi

# Ick. BPF requires pahole "supernew" to work
cd $(mktemp -d) && git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git && \
    cd pahole && mkdir build && cd build && cmake -D__LIB=lib .. && make install

dpkg --add-architecture riscv64
if [[ $debarch == "arm64" ]]; then
    sed -i "s/^deb/deb [arch=${debarch}]/" /etc/apt/sources.list
    cat <<EOF >> /etc/apt/sources.list
deb [arch=riscv64] http://ports.ubuntu.com/ubuntu-ports jammy main restricted multiverse universe
deb [arch=riscv64] http://ports.ubuntu.com/ubuntu-ports jammy-updates main
deb [arch=riscv64] http://ports.ubuntu.com/ubuntu-ports jammy-security main
EOF
fi

apt-get update

apt-get install --yes --no-install-recommends \
    libasound2-dev:riscv64 \
    libc6-dev:riscv64 \
    libcap-dev:riscv64 \
    libcap-ng-dev:riscv64 \
    libelf-dev:riscv64 \
    libfuse-dev:riscv64 \
    libhugetlbfs-dev:riscv64 \
    libmnl-dev:riscv64 \
    libnuma-dev:riscv64 \
    libpopt-dev:riscv64 \
    libssl-dev:riscv64 \
    liburing-dev:riscv64

export PIPX_HOME=/root/.local/pipx/venvs
export PIPX_BIN_DIR=/root/.local/bin
pipx install tuxmake
pipx install dtschema

echo 'export PATH=${PATH}:/root/.local/bin' >> ~/.bashrc

if [[ $debarch == "amd64" ]]; then
    exit 0
fi

register_clang_version() {
    local version=$1
    local priority=$2

    update-alternatives \
        --install /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-${version} ${priority} \
        --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-${version} \
        --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-${version} \
        --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-${version} \
        --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-${version} \
        --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-${version} \
        --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-${version} \
        --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-${version} \
        --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-${version} \
        --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-${version} \
        --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-${version} \
        --slave   /usr/bin/llvm-mcmarkup     llvm-mcmarkup    /usr/bin/llvm-mcmarkup-${version} \
        --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-${version} \
        --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-${version} \
        --slave   /usr/bin/llvm-objcopy      llvm-objcopy     /usr/bin/llvm-objcopy-${version} \
        --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-${version} \
        --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-${version} \
        --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-${version} \
        --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-${version} \
        --slave   /usr/bin/llvm-strip        llvm-strip       /usr/bin/llvm-strip-${version} \
        --slave   /usr/bin/llvm-readelf      llvm-readelf     /usr/bin/llvm-readelf-${version} \
        --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-${version} \
        --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-${version} \
        --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-${version}

    update-alternatives \
        --install /usr/bin/clang                 clang                 /usr/bin/clang-${version} ${priority} \
        --slave   /usr/bin/clang++               clang++               /usr/bin/clang++-${version}  \
        --slave   /usr/bin/asan_symbolize        asan_symbolize        /usr/bin/asan_symbolize-${version} \
        --slave   /usr/bin/c-index-test          c-index-test          /usr/bin/c-index-test-${version} \
        --slave   /usr/bin/clang-check           clang-check           /usr/bin/clang-check-${version} \
        --slave   /usr/bin/clang-cl              clang-cl              /usr/bin/clang-cl-${version} \
        --slave   /usr/bin/clang-cpp             clang-cpp             /usr/bin/clang-cpp-${version} \
        --slave   /usr/bin/clang-format          clang-format          /usr/bin/clang-format-${version} \
        --slave   /usr/bin/clang-format-diff     clang-format-diff     /usr/bin/clang-format-diff-${version} \
        --slave   /usr/bin/clang-import-test     clang-import-test     /usr/bin/clang-import-test-${version} \
        --slave   /usr/bin/clang-include-fixer   clang-include-fixer   /usr/bin/clang-include-fixer-${version} \
        --slave   /usr/bin/clang-offload-bundler clang-offload-bundler /usr/bin/clang-offload-bundler-${version} \
        --slave   /usr/bin/clang-query           clang-query           /usr/bin/clang-query-${version} \
        --slave   /usr/bin/clang-rename          clang-rename          /usr/bin/clang-rename-${version} \
        --slave   /usr/bin/clang-reorder-fields  clang-reorder-fields  /usr/bin/clang-reorder-fields-${version} \
        --slave   /usr/bin/clang-tidy            clang-tidy            /usr/bin/clang-tidy-${version} \
        --slave   /usr/bin/lldb                  lldb                  /usr/bin/lldb-${version} \
        --slave   /usr/bin/lldb-server           lldb-server           /usr/bin/lldb-server-${version} \
        --slave   /usr/bin/ld.lld                lld                   /usr/bin/ld.lld-${version}
}

register_clang_version 18 1
