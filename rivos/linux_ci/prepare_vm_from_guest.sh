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

sudo apt update
sudo apt install -y make gcc yacc flex bison

prepare_image_uefi
prepare_image_initramfs
prepare_image_misc
