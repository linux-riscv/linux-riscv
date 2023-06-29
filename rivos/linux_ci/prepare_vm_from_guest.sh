#!/bin/bash

prepare_image_uefi() {
	# Remove u-boot-menu (which creates extlinux.conf)
	sudo apt remove -y u-boot-menu
	# Remove extlinux
	sudo rm -f /boot/extlinux/extlinux.conf

	# Install grub2
	sudo apt install -y grub-efi-riscv64
	sudo grub-install
	sudo update-grub2
}

prepare_image_initramfs() {
	# initramfs creation is *very* long, with the following, it takes only ~2min
	# TODO check that it is not already in
	sudo bash -c "echo virtio_blk >> /etc/initramfs-tools/modules"
	sudo sed -i 's/MODULES=most/MODULES=list/g' /etc/initramfs-tools/initramfs.conf
	sudo sed -i 's/COMPRESS=zstd/COMPRESS=gzip/g' /etc/initramfs-tools/initramfs.conf

	# Remove this package after initramfs.conf modifications
	sudo apt remove -y cryptsetup-initramfs
}

prepare_image_misc() {
	# Disable unattended-upgrades
	sudo sed -i 's/Update-Package-Lists \"1\"/Update-Package-Lists \"0\"/g' /etc/apt/apt.conf.d/20auto-upgrades
	sudo sed -i 's/Unattended-Upgrade \"1\"/Unattended-Upgrade \"0\"/g' /etc/apt/apt.conf.d/20auto-upgrades
}

prepare_image_install_ltp() {
	pushd /home/ubuntu

	sudo apt install -y git
	git clone https://github.com/linux-test-project/ltp -b 20220930
	cd ltp
	sudo bash ci/debian.sh

	make autotools

	# tests failing to build:
	# * testcases/kernel/device-drivers/block/block_dev_kernel/ltp_block_dev.c:15:10: fatal error: linux/genhd.h: No such file or directory
	# * testcases/kernel/device-drivers/acpi/ltp_acpi_cmds.c:39:10: fatal error: linux/genhd.h: No such file or directory
	# * testcases/kernel/device-drivers/tbio/tbio_kernel/ltp_tbio.c:46:10: fatal error: linux/genhd.h: No such file or directory
	# So let's skip the modules for now as we can't prebuild them.
	./configure --without-modules
	make -j$(nproc)
	sudo make install

	popd
}

prepare_image_install_kselftests() {
	pushd /home/ubuntu

	sudo apt install -y flex bison libmount-dev libcap-ng-dev libfuse-dev libpopt-dev libnuma-dev libasound2-dev libmnl-dev libcap-dev

	# FIXME: We need another way to test other branches here.
	#git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.ba.rivosinc.com/rv/sw/ext/linux --depth 1 -b dev/alex/ubuntu_ci_v1
	git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git --depth 1 -b v6.1

	cd linux
	make O=build_kselftests defconfig
	make O=build_kselftests kselftest-merge
	make O=build_kselftests headers
	make O=build_kselftests FORMAT= SKIP_TARGETS="bpf arm64 ia64 powerpc sparc64 x86" -C tools/testing/selftests -j$(nproc) gen_tar

	sudo mkdir /opt/kselftests
	cd /opt/kselftests
	sudo tar xvf /home/ubuntu/linux/build_kselftests/kselftest/kselftest_install/kselftest-packages/kselftest.tar

	# Remove tests that cause panic
	# This one seems legit
	rm ./drivers/net/bonding/bond-arp-interval-causes-panic.sh
	# This one needs debug
	rm ./net/af_unix/diag_uid

	# Increase timeout
	echo "timeout=900" > settings
	for i in `grep -io '^[a-z0-9/]\+' ./kselftest-list.txt | sort | uniq`; do cp settings $i; done

	popd
}

sudo apt update

prepare_image_uefi
prepare_image_initramfs
prepare_image_install_ltp
prepare_image_install_kselftests
prepare_image_misc
