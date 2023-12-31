// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SHA256 implementation for RISC-V 64
 *
 * Copyright (C) 2022 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/types.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha256_base.h>

/*
 * sha256 using zvkb and zvknha/b vector crypto extension
 *
 * This asm function will just take the first 256-bit as the sha256 state from
 * the pointer to `struct sha256_state`.
 */
asmlinkage void
sha256_block_data_order_zvkb_zvknha_or_zvknhb(struct sha256_state *digest,
					      const u8 *data, int num_blks);

static int riscv64_sha256_update(struct shash_desc *desc, const u8 *data,
				 unsigned int len)
{
	int ret = 0;

	/*
	 * Make sure struct sha256_state begins directly with the SHA256
	 * 256-bit internal state, as this is what the asm function expect.
	 */
	BUILD_BUG_ON(offsetof(struct sha256_state, state) != 0);

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		ret = sha256_base_do_update(
			desc, data, len,
			sha256_block_data_order_zvkb_zvknha_or_zvknhb);
		kernel_vector_end();
	} else {
		ret = crypto_sha256_update(desc, data, len);
	}

	return ret;
}

static int riscv64_sha256_finup(struct shash_desc *desc, const u8 *data,
				unsigned int len, u8 *out)
{
	if (crypto_simd_usable()) {
		kernel_vector_begin();
		if (len)
			sha256_base_do_update(
				desc, data, len,
				sha256_block_data_order_zvkb_zvknha_or_zvknhb);
		sha256_base_do_finalize(
			desc, sha256_block_data_order_zvkb_zvknha_or_zvknhb);
		kernel_vector_end();

		return sha256_base_finish(desc, out);
	}

	return crypto_sha256_finup(desc, data, len, out);
}

static int riscv64_sha256_final(struct shash_desc *desc, u8 *out)
{
	return riscv64_sha256_finup(desc, NULL, 0, out);
}

static struct shash_alg sha256_algs[] = {
	{
		.init = sha256_base_init,
		.update = riscv64_sha256_update,
		.final = riscv64_sha256_final,
		.finup = riscv64_sha256_finup,
		.descsize = sizeof(struct sha256_state),
		.digestsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_blocksize = SHA256_BLOCK_SIZE,
			.cra_priority = 150,
			.cra_name = "sha256",
			.cra_driver_name = "sha256-riscv64-zvknha_or_zvknhb-zvkb",
			.cra_module = THIS_MODULE,
		},
	}, {
		.init = sha224_base_init,
		.update = riscv64_sha256_update,
		.final = riscv64_sha256_final,
		.finup = riscv64_sha256_finup,
		.descsize = sizeof(struct sha256_state),
		.digestsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_blocksize = SHA224_BLOCK_SIZE,
			.cra_priority = 150,
			.cra_name = "sha224",
			.cra_driver_name = "sha224-riscv64-zvknha_or_zvknhb-zvkb",
			.cra_module = THIS_MODULE,
		},
	},
};

static inline bool check_sha256_ext(void)
{
	/*
	 * From the spec:
	 * The Zvknhb ext supports both SHA-256 and SHA-512 and Zvknha only
	 * supports SHA-256.
	 */
	return (riscv_isa_extension_available(NULL, ZVKNHA) ||
		riscv_isa_extension_available(NULL, ZVKNHB)) &&
	       riscv_isa_extension_available(NULL, ZVKB) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_sha256_mod_init(void)
{
	if (check_sha256_ext())
		return crypto_register_shashes(sha256_algs,
					       ARRAY_SIZE(sha256_algs));

	return -ENODEV;
}

static void __exit riscv64_sha256_mod_fini(void)
{
	crypto_unregister_shashes(sha256_algs, ARRAY_SIZE(sha256_algs));
}

module_init(riscv64_sha256_mod_init);
module_exit(riscv64_sha256_mod_fini);

MODULE_DESCRIPTION("SHA-256 (RISC-V accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sha224");
MODULE_ALIAS_CRYPTO("sha256");
