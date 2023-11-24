// SPDX-License-Identifier: GPL-2.0-only
/* dtso - used for functional tests of memory consistency model switching
 * at run-time.
 *
 * Copyright (c) 2023 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>

#include "../hwprobe/hwprobe.h"
#include "../../kselftest_harness.h"

/*
 * We have the following cases:
 * 1) DTSO support disabed in the kernel config:
 *    - Ssdtso is not detected
 *    - {G,S}ET_MEMORY_CONSISTENCY_MODEL fails with EINVAL
 * 2) DTSO support enabled and Ssdtso not available:
 *    - Ssdtso is not detected
 *    - {G,S}ET_MEMORY_CONSISTENCY_MODEL works for WMO and fails for TSO with EINVAL:
 * 3) DTSO support enabled and Ssdtso available
 *    - Ssdtso is detected
 *    - {G,S}ET_MEMORY_CONSISTENCY_MODEL works for WMO and TSO
 */

TEST(dtso)
{
	struct riscv_hwprobe pair;
	int ret;
	bool ssdtso_configured;
	bool ssdtso_available;

	ret = prctl(PR_GET_MEMORY_CONSISTENCY_MODEL);
	if (ret < 0) {
		ASSERT_EQ(errno, EINVAL);
		ssdtso_configured = false;
	} else {
		ASSERT_TRUE(ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO ||
			    ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO);
		ssdtso_configured = true;
	}

	pair.key = RISCV_HWPROBE_KEY_IMA_EXT_0;
	ret = riscv_hwprobe(&pair, 1, 0, NULL, 0);
	ASSERT_GE(ret, 0);
	ASSERT_EQ(pair.key, RISCV_HWPROBE_KEY_IMA_EXT_0);
	ssdtso_available = !!(pair.value & RISCV_HWPROBE_EXT_SSDTSO);

	if (ssdtso_configured) {
		ret = prctl(PR_GET_MEMORY_CONSISTENCY_MODEL);
		ASSERT_TRUE(ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO ||
			    ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO);

		if (ssdtso_available) {
			ret = prctl(PR_SET_MEMORY_CONSISTENCY_MODEL,
				    PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO);
			ASSERT_EQ(ret, 0);
			ret = prctl(PR_GET_MEMORY_CONSISTENCY_MODEL);
			ASSERT_TRUE(ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO);
		} else {
			ksft_test_result_skip("Ssdtso not available\n");
		}

		ret = prctl(PR_SET_MEMORY_CONSISTENCY_MODEL,
			    PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO);
		ASSERT_EQ(ret, 0);
		ret = prctl(PR_GET_MEMORY_CONSISTENCY_MODEL);
		ASSERT_TRUE(ret == PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO);
	} else {
		ASSERT_EQ(ssdtso_available, false);
		ksft_test_result_skip("Ssdtso not configured\n");
	}
}

TEST_HARNESS_MAIN
