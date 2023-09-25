#!/bin/bash -x

# We want to exit in error as soon as a command returns a non-zero exit code
set -e

# Install dependencies
# for growpart
sudo apt update
sudo apt install -y cloud-guest-utils

# Download and extract the VM
ubuntu_vm_version="23.04"
ubuntu_vm_name="ubuntu-$ubuntu_vm_version-preinstalled-server-riscv64+unmatched.img"
if [ ! -f "$ubuntu_vm_name" ]; then
    wget --no-verbose https://cdimage.ubuntu.com/releases/$ubuntu_vm_version/release/$ubuntu_vm_name.xz
    xz -d $ubuntu_vm_name.xz
fi

# Increase rootfs partition
qemu-img resize $ubuntu_vm_name +8G
loop_dev=`sudo losetup --partscan -f --show $ubuntu_vm_name`
sudo growpart ${loop_dev} 1

# workaround for e2fsck < 1.47
#sudo tune2fs -O ^orphan_file "${loop_dev}p1"

sudo e2fsck -f "${loop_dev}p1" -y
sudo resize2fs "${loop_dev}p1" 12G
# Remove expiration of the initial password
sudo mount "${loop_dev}p1" /mnt
sudo sed -i 's/expire: True/expire: False/g' /mnt/var/lib/cloud/seed/nocloud-net/user-data
sudo umount "${loop_dev}p1"
sudo losetup -d "${loop_dev}"

# Remove previous ssh key
#ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:10022"

# Download u-boot from Ubuntu Kinetic
# FIXME
mkdir -p firmware
wget http://launchpadlibrarian.net/636498883/u-boot-qemu_2022.07+dfsg-1ubuntu4.2_all.deb
dpkg-deb --extract u-boot-qemu_2022.07+dfsg-1ubuntu4.2_all.deb firmware/
