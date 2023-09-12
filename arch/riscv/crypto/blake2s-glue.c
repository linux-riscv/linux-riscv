// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2022 Rivos, Inc. All Rights Reserved.
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <crypto/internal/blake2s.h>

#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/sizes.h>

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/simd.h>
#include <asm/vector.h>

asmlinkage void blake2s_compress_vector(struct blake2s_state *state, const u8 *block,
					const size_t nblocks, const u32 inc);

void blake2s_compress(struct blake2s_state *state, const u8 *block, size_t nblocks, const u32 inc)
{
	if (!(has_vector() && riscv_v_vsize >= 256 * 32 / 8) || !may_use_simd()) {
		blake2s_compress_generic(state, block, nblocks, inc);
		return;
	}

	do {
		const size_t blocks = min_t(size_t, nblocks, SZ_4K / BLAKE2S_BLOCK_SIZE);

		kernel_vector_begin();
		blake2s_compress_vector(state, block, blocks, inc);
		kernel_vector_end();

		nblocks -= blocks;
		block += blocks * BLAKE2S_BLOCK_SIZE;
	} while (nblocks);
}
EXPORT_SYMBOL(blake2s_compress);
