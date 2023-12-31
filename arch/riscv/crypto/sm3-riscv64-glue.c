// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SM3 implementation for RISC-V 64
 *
 * Copyright (C) 2023 VRULL GmbH
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
#include <crypto/sm3_base.h>

/*
 * sm3 using zvksh vector crypto extension
 *
 * This asm function will just take the first 256-bit as the sm3 state from
 * the pointer to `struct sm3_state`.
 */
asmlinkage void ossl_hwsm3_block_data_order_zvksh(struct sm3_state *digest,
						  u8 const *o, int num);

static int riscv64_sm3_update(struct shash_desc *desc, const u8 *data,
			      unsigned int len)
{
	int ret = 0;

	/*
	 * Make sure struct sm3_state begins directly with the SM3 256-bit internal
	 * state, as this is what the asm function expect.
	 */
	BUILD_BUG_ON(offsetof(struct sm3_state, state) != 0);

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		ret = sm3_base_do_update(desc, data, len,
					 ossl_hwsm3_block_data_order_zvksh);
		kernel_vector_end();
	} else {
		sm3_update(shash_desc_ctx(desc), data, len);
	}

	return ret;
}

static int riscv64_sm3_finup(struct shash_desc *desc, const u8 *data,
			     unsigned int len, u8 *out)
{
	struct sm3_state *ctx;

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		if (len)
			sm3_base_do_update(desc, data, len,
					   ossl_hwsm3_block_data_order_zvksh);
		sm3_base_do_finalize(desc, ossl_hwsm3_block_data_order_zvksh);
		kernel_vector_end();

		return sm3_base_finish(desc, out);
	}

	ctx = shash_desc_ctx(desc);
	if (len)
		sm3_update(ctx, data, len);
	sm3_final(ctx, out);

	return 0;
}

static int riscv64_sm3_final(struct shash_desc *desc, u8 *out)
{
	return riscv64_sm3_finup(desc, NULL, 0, out);
}

static struct shash_alg sm3_alg = {
	.init = sm3_base_init,
	.update = riscv64_sm3_update,
	.final = riscv64_sm3_final,
	.finup = riscv64_sm3_finup,
	.descsize = sizeof(struct sm3_state),
	.digestsize = SM3_DIGEST_SIZE,
	.base = {
		.cra_blocksize = SM3_BLOCK_SIZE,
		.cra_priority = 150,
		.cra_name = "sm3",
		.cra_driver_name = "sm3-riscv64-zvksh-zvkb",
		.cra_module = THIS_MODULE,
	},
};

static inline bool check_sm3_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKSH) &&
	       riscv_isa_extension_available(NULL, ZVKB) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_sm3_mod_init(void)
{
	if (check_sm3_ext())
		return crypto_register_shash(&sm3_alg);

	return -ENODEV;
}

static void __exit riscv64_sm3_mod_fini(void)
{
	crypto_unregister_shash(&sm3_alg);
}

module_init(riscv64_sm3_mod_init);
module_exit(riscv64_sm3_mod_fini);

MODULE_DESCRIPTION("SM3 (RISC-V accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sm3");
