// SPDX-License-Identifier: GPL-2.0-only
/*
 * Linux/riscv64 port of the OpenSSL SM4 implementation for RISC-V 64
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/sm4.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/types.h>

/* sm4 using zvksed vector crypto extension */
asmlinkage void rv64i_zvksed_sm4_encrypt(const u8 *in, u8 *out, const u32 *key);
asmlinkage void rv64i_zvksed_sm4_decrypt(const u8 *in, u8 *out, const u32 *key);
asmlinkage int rv64i_zvksed_sm4_set_key(const u8 *user_key,
					unsigned int key_len, u32 *enc_key,
					u32 *dec_key);

static int riscv64_sm4_setkey_zvksed(struct crypto_tfm *tfm, const u8 *key,
				     unsigned int key_len)
{
	struct sm4_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret = 0;

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		if (rv64i_zvksed_sm4_set_key(key, key_len, ctx->rkey_enc,
					     ctx->rkey_dec))
			ret = -EINVAL;
		kernel_vector_end();
	} else {
		ret = sm4_expandkey(ctx, key, key_len);
	}

	return ret;
}

static void riscv64_sm4_encrypt_zvksed(struct crypto_tfm *tfm, u8 *dst,
				       const u8 *src)
{
	const struct sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		rv64i_zvksed_sm4_encrypt(src, dst, ctx->rkey_enc);
		kernel_vector_end();
	} else {
		sm4_crypt_block(ctx->rkey_enc, dst, src);
	}
}

static void riscv64_sm4_decrypt_zvksed(struct crypto_tfm *tfm, u8 *dst,
				       const u8 *src)
{
	const struct sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		rv64i_zvksed_sm4_decrypt(src, dst, ctx->rkey_dec);
		kernel_vector_end();
	} else {
		sm4_crypt_block(ctx->rkey_dec, dst, src);
	}
}

static struct crypto_alg riscv64_sm4_zvksed_zvkb_alg = {
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = SM4_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sm4_ctx),
	.cra_priority = 300,
	.cra_name = "sm4",
	.cra_driver_name = "sm4-riscv64-zvksed-zvkb",
	.cra_cipher = {
		.cia_min_keysize = SM4_KEY_SIZE,
		.cia_max_keysize = SM4_KEY_SIZE,
		.cia_setkey = riscv64_sm4_setkey_zvksed,
		.cia_encrypt = riscv64_sm4_encrypt_zvksed,
		.cia_decrypt = riscv64_sm4_decrypt_zvksed,
	},
	.cra_module = THIS_MODULE,
};

static inline bool check_sm4_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKSED) &&
	       riscv_isa_extension_available(NULL, ZVKB) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_sm4_mod_init(void)
{
	if (check_sm4_ext())
		return crypto_register_alg(&riscv64_sm4_zvksed_zvkb_alg);

	return -ENODEV;
}

static void __exit riscv64_sm4_mod_fini(void)
{
	crypto_unregister_alg(&riscv64_sm4_zvksed_zvkb_alg);
}

module_init(riscv64_sm4_mod_init);
module_exit(riscv64_sm4_mod_fini);

MODULE_DESCRIPTION("SM4 (RISC-V accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sm4");
