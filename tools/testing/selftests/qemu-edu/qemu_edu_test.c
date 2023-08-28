// SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
// Confidential and proprietary, see LICENSE for details.
// SPDX-License-Identifier: LicenseRef-Rivos-Internal-Only

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/memfd.h>
#include <time.h>

/* if not defined ... */
int memfd_create(const char *__name, unsigned int __flags) __THROW;

int main(int argn, char *argv[])
{
	/*
	 * Adding debug printf generates network traffic, with additional IOTLB cache polution
	 * and uncorrelated IOTLB cache invalidation requests from network stack.
	 * Keep test as I/O quied as possible to limit IOMMU map/unmap not related to the test.
	 */
	const int use_print = 0;
	/*
	 * Page request interface implementation for qemu-edu device is simplified, and relies
	 * on timely processing of the page-request. Ensure memory used by the test buffer is
	 *  populated and locked to work around this limitation.
	 */
	const int use_mlock = 0;

	const size_t len = 256;
	const size_t pgs = getpagesize();
	const size_t mfd_cnt = 64;
	int mfd, rot;
	int fd, ret;
	char ref[len];
	char *dev, *src, *dst;
	int count = 1;

	/* QEMU EDU bounce buffer location */
	const size_t tmp = 0x40000;

	if (argn < 2) {
		dev = "/dev/qemu-edu";
	} else {
		dev = argv[1];
	}

	if (argn > 2) {
		count = atoi(argv[2]);
	}

	srand((unsigned)time(NULL));

	/* qemu-edu device node */
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("Can not open %s, err: %d\n", argv[1], fd);
		return -1;
	}

	/* pool of physical pages for mapping pseudo-randomization */
	mfd = memfd_create("buffer", MFD_CLOEXEC | 0x10U /* MFD_EXEC */ );
	if (mfd < 0) {
		printf("Can not create memfd, err: %d\n", mfd);
		return -1;
	}
	ftruncate(mfd, pgs * mfd_cnt);

	rot = 0;
	src = NULL;
	dst = NULL;

 retry:
	/* reuse src and dst virtual addresses if already assigned in prev iteration. */
	src =
	    mmap(src, pgs, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, mfd,
		 rot * pgs);
	rot = (rot + 1) % mfd_cnt;

	dst =
	    mmap(dst, pgs, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, mfd,
		 rot * pgs);
	rot = (rot + 1) % mfd_cnt;

	memset(ref, 0xa5, len);
	snprintf(ref, len, "Lorem Ipsum @ %x", rand());

	memcpy(src, ref, len);

	if (use_mlock)
		mlock(src, len);
	ret = pwrite(fd, src, len, tmp);
	if (use_mlock)
		munlock(src, len);

	if (ret < 0) {
		printf("Can not write, error %d\n", ret);
	}

	if (use_mlock)
		mlock(dst, len);
	ret = pread(fd, dst, len, tmp);
	if (use_mlock)
		munlock(dst, len);

	if (ret < 0) {
		printf("Can not read, error %d\n", ret);
	}

	if (memcmp(src, ref, len)) {
		printf("ERROR\nsrc: %p  - %s\nref: %p  - %s\n", src, (char *)src, ref,
		       (char *)ref);
		return -1;
	}

	if (memcmp(dst, ref, len)) {
		printf("ERROR\ndst: %p  - %s\nref: %p  - %s\n", dst, (char *)dst, ref,
		       (char *)ref);
		return -1;
	}

	if (use_print)
		printf("src: %p  - %s\ndst: %p  - %s\n", src, (char *)src, dst,
		       (char *)dst);

	madvise(src, pgs, MADV_DONTNEED);
	munmap(src, pgs);

	madvise(dst, pgs, MADV_DONTNEED);
	munmap(dst, pgs);

	if (--count > 0) {
		goto retry;
	}

	close(fd);

	return 0;
}
