#!/bin/bash

git clone https://github.com/libhugetlbfs/libhugetlbfs
cd libhugetlbfs
patch -p1 < ../0003-Disable-hugepage-backed-malloc-if-__morecore-is-not-.patch
make -j8

mkdir -p ~/hugetlbfs-64
sudo mount -t hugetlbfs none -opagesize=64k ~/hugetlbfs-64

sudo bash -c "echo 50 > /sys/devices/system/node/node0/hugepages/hugepages-64kB/nr_hugepages"
sudo bash -c "echo 50 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"

time make check
