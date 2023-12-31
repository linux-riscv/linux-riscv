// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V optimized GHASH routines
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/ghash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <linux/crypto.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/types.h>

/* ghash using zvkg vector crypto extension */
asmlinkage void gcm_ghash_rv64i_zvkg(be128 *Xi, const be128 *H, const u8 *inp,
				     size_t len);

struct riscv64_ghash_tfm_ctx {
	be128 key;
};

struct riscv64_ghash_desc_ctx {
	be128 shash;
	u8 buffer[GHASH_BLOCK_SIZE];
	u32 bytes;
};

static inline void ghash_blocks(const struct riscv64_ghash_tfm_ctx *tctx,
				struct riscv64_ghash_desc_ctx *dctx,
				const u8 *src, size_t srclen)
{
	/* The srclen is nonzero and a multiple of 16. */
	if (crypto_simd_usable()) {
		kernel_vector_begin();
		gcm_ghash_rv64i_zvkg(&dctx->shash, &tctx->key, src, srclen);
		kernel_vector_end();
	} else {
		do {
			crypto_xor((u8 *)&dctx->shash, src, GHASH_BLOCK_SIZE);
			gf128mul_lle(&dctx->shash, &tctx->key);
			srclen -= GHASH_BLOCK_SIZE;
			src += GHASH_BLOCK_SIZE;
		} while (srclen);
	}
}

static int ghash_init(struct shash_desc *desc)
{
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	*dctx = (struct riscv64_ghash_desc_ctx){};

	return 0;
}

static int ghash_update_zvkg(struct shash_desc *desc, const u8 *src,
			     unsigned int srclen)
{
	size_t len;
	const struct riscv64_ghash_tfm_ctx *tctx = crypto_shash_ctx(desc->tfm);
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	if (dctx->bytes) {
		if (dctx->bytes + srclen < GHASH_BLOCK_SIZE) {
			memcpy(dctx->buffer + dctx->bytes, src, srclen);
			dctx->bytes += srclen;
			return 0;
		}
		memcpy(dctx->buffer + dctx->bytes, src,
		       GHASH_BLOCK_SIZE - dctx->bytes);

		ghash_blocks(tctx, dctx, dctx->buffer, GHASH_BLOCK_SIZE);

		src += GHASH_BLOCK_SIZE - dctx->bytes;
		srclen -= GHASH_BLOCK_SIZE - dctx->bytes;
		dctx->bytes = 0;
	}
	len = srclen & ~(GHASH_BLOCK_SIZE - 1);

	if (len) {
		ghash_blocks(tctx, dctx, src, len);
		src += len;
		srclen -= len;
	}

	if (srclen) {
		memcpy(dctx->buffer, src, srclen);
		dctx->bytes = srclen;
	}

	return 0;
}

static int ghash_final_zvkg(struct shash_desc *desc, u8 *out)
{
	const struct riscv64_ghash_tfm_ctx *tctx = crypto_shash_ctx(desc->tfm);
	struct riscv64_ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	int i;

	if (dctx->bytes) {
		for (i = dctx->bytes; i < GHASH_BLOCK_SIZE; i++)
			dctx->buffer[i] = 0;

		ghash_blocks(tctx, dctx, dctx->buffer, GHASH_BLOCK_SIZE);
	}

	memcpy(out, &dctx->shash, GHASH_DIGEST_SIZE);

	return 0;
}

static int ghash_setkey(struct crypto_shash *tfm, const u8 *key,
			unsigned int keylen)
{
	struct riscv64_ghash_tfm_ctx *tctx = crypto_shash_ctx(tfm);

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	memcpy(&tctx->key, key, GHASH_BLOCK_SIZE);

	return 0;
}

static struct shash_alg riscv64_ghash_alg_zvkg = {
	.init = ghash_init,
	.update = ghash_update_zvkg,
	.final = ghash_final_zvkg,
	.setkey = ghash_setkey,
	.descsize = sizeof(struct riscv64_ghash_desc_ctx),
	.digestsize = GHASH_DIGEST_SIZE,
	.base = {
		.cra_blocksize = GHASH_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_ghash_tfm_ctx),
		.cra_priority = 303,
		.cra_name = "ghash",
		.cra_driver_name = "ghash-riscv64-zvkg",
		.cra_module = THIS_MODULE,
	},
};

static inline bool check_ghash_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKG) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_ghash_mod_init(void)
{
	if (check_ghash_ext())
		return crypto_register_shash(&riscv64_ghash_alg_zvkg);

	return -ENODEV;
}

static void __exit riscv64_ghash_mod_fini(void)
{
	crypto_unregister_shash(&riscv64_ghash_alg_zvkg);
}

module_init(riscv64_ghash_mod_init);
module_exit(riscv64_ghash_mod_fini);

MODULE_DESCRIPTION("GCM GHASH (RISC-V accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("ghash");
