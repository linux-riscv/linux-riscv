// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port of the OpenSSL ChaCha20 implementation for RISC-V 64
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/vector.h>
#include <crypto/internal/chacha.h>
#include <crypto/internal/skcipher.h>
#include <linux/crypto.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/types.h>

/* chacha20 using zvkb vector crypto extension */
asmlinkage void ChaCha20_ctr32_zvkb(u8 *out, const u8 *input, size_t len,
				    const u32 *key, const u32 *counter);

static int riscv64_chacha20_encrypt(struct skcipher_request *req)
{
	u32 iv[CHACHA_IV_SIZE / sizeof(u32)];
	u8 block_buffer[CHACHA_BLOCK_SIZE];
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct chacha_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	unsigned int tail_bytes;
	int err;

	iv[0] = get_unaligned_le32(req->iv);
	iv[1] = get_unaligned_le32(req->iv + 4);
	iv[2] = get_unaligned_le32(req->iv + 8);
	iv[3] = get_unaligned_le32(req->iv + 12);

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes) {
		nbytes = walk.nbytes & (~(CHACHA_BLOCK_SIZE - 1));
		tail_bytes = walk.nbytes & (CHACHA_BLOCK_SIZE - 1);
		kernel_vector_begin();
		if (nbytes) {
			ChaCha20_ctr32_zvkb(walk.dst.virt.addr,
					    walk.src.virt.addr, nbytes,
					    ctx->key, iv);
			iv[0] += nbytes / CHACHA_BLOCK_SIZE;
		}
		if (walk.nbytes == walk.total && tail_bytes > 0) {
			memcpy(block_buffer, walk.src.virt.addr + nbytes,
			       tail_bytes);
			ChaCha20_ctr32_zvkb(block_buffer, block_buffer,
					    CHACHA_BLOCK_SIZE, ctx->key, iv);
			memcpy(walk.dst.virt.addr + nbytes, block_buffer,
			       tail_bytes);
			tail_bytes = 0;
		}
		kernel_vector_end();

		err = skcipher_walk_done(&walk, tail_bytes);
	}

	return err;
}

static struct skcipher_alg riscv64_chacha_alg_zvkb = {
	.setkey = chacha20_setkey,
	.encrypt = riscv64_chacha20_encrypt,
	.decrypt = riscv64_chacha20_encrypt,
	.min_keysize = CHACHA_KEY_SIZE,
	.max_keysize = CHACHA_KEY_SIZE,
	.ivsize = CHACHA_IV_SIZE,
	.chunksize = CHACHA_BLOCK_SIZE,
	.walksize = CHACHA_BLOCK_SIZE * 4,
	.base = {
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct chacha_ctx),
		.cra_priority = 300,
		.cra_name = "chacha20",
		.cra_driver_name = "chacha20-riscv64-zvkb",
		.cra_module = THIS_MODULE,
	},
};

static inline bool check_chacha20_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKB) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_chacha_mod_init(void)
{
	if (check_chacha20_ext())
		return crypto_register_skcipher(&riscv64_chacha_alg_zvkb);

	return -ENODEV;
}

static void __exit riscv64_chacha_mod_fini(void)
{
	crypto_unregister_skcipher(&riscv64_chacha_alg_zvkb);
}

module_init(riscv64_chacha_mod_init);
module_exit(riscv64_chacha_mod_fini);

MODULE_DESCRIPTION("ChaCha20 (RISC-V accelerated)");
MODULE_AUTHOR("Jerry Shih <jerry.shih@sifive.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("chacha20");
