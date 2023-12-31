// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port of the OpenSSL AES block mode implementations for RISC-V
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/vector.h>
#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/xts.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/crypto.h>
#include <linux/linkage.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/types.h>

#include "aes-riscv64-glue.h"

struct riscv64_aes_xts_ctx {
	struct crypto_aes_ctx ctx1;
	struct crypto_aes_ctx ctx2;
};

/* aes cbc block mode using zvkned vector crypto extension */
asmlinkage void rv64i_zvkned_cbc_encrypt(const u8 *in, u8 *out, size_t length,
					 const struct crypto_aes_ctx *key,
					 u8 *ivec);
asmlinkage void rv64i_zvkned_cbc_decrypt(const u8 *in, u8 *out, size_t length,
					 const struct crypto_aes_ctx *key,
					 u8 *ivec);
/* aes ecb block mode using zvkned vector crypto extension */
asmlinkage void rv64i_zvkned_ecb_encrypt(const u8 *in, u8 *out, size_t length,
					 const struct crypto_aes_ctx *key);
asmlinkage void rv64i_zvkned_ecb_decrypt(const u8 *in, u8 *out, size_t length,
					 const struct crypto_aes_ctx *key);

/* aes ctr block mode using zvkb and zvkned vector crypto extension */
/* This func operates on 32-bit counter. Caller has to handle the overflow. */
asmlinkage void
rv64i_zvkb_zvkned_ctr32_encrypt_blocks(const u8 *in, u8 *out, size_t length,
				       const struct crypto_aes_ctx *key,
				       u8 *ivec);

/* aes xts block mode using zvbb, zvkg and zvkned vector crypto extension */
asmlinkage void
rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(const u8 *in, u8 *out, size_t length,
				       const struct crypto_aes_ctx *key, u8 *iv,
				       int update_iv);
asmlinkage void
rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(const u8 *in, u8 *out, size_t length,
				       const struct crypto_aes_ctx *key, u8 *iv,
				       int update_iv);

/* ecb */
static int riscv64_aes_setkey(struct crypto_skcipher *tfm, const u8 *in_key,
			      unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);

	return riscv64_aes_setkey_zvkned(ctx, in_key, key_len);
}

static int riscv64_ecb_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	/* If we have error here, the `nbytes` will be zero. */
	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_ecb_encrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & ~(AES_BLOCK_SIZE - 1), ctx);
		kernel_vector_end();
		err = skcipher_walk_done(&walk, nbytes & (AES_BLOCK_SIZE - 1));
	}

	return err;
}

static int riscv64_ecb_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_ecb_decrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & ~(AES_BLOCK_SIZE - 1), ctx);
		kernel_vector_end();
		err = skcipher_walk_done(&walk, nbytes & (AES_BLOCK_SIZE - 1));
	}

	return err;
}

/* cbc */
static int riscv64_cbc_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_cbc_encrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & ~(AES_BLOCK_SIZE - 1), ctx,
					 walk.iv);
		kernel_vector_end();
		err = skcipher_walk_done(&walk, nbytes & (AES_BLOCK_SIZE - 1));
	}

	return err;
}

static int riscv64_cbc_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_cbc_decrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & ~(AES_BLOCK_SIZE - 1), ctx,
					 walk.iv);
		kernel_vector_end();
		err = skcipher_walk_done(&walk, nbytes & (AES_BLOCK_SIZE - 1));
	}

	return err;
}

/* ctr */
static int riscv64_ctr_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int ctr32;
	unsigned int nbytes;
	unsigned int blocks;
	unsigned int current_blocks;
	unsigned int current_length;
	int err;

	/* the ctr iv uses big endian */
	ctr32 = get_unaligned_be32(req->iv + 12);
	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		if (nbytes != walk.total) {
			nbytes &= ~(AES_BLOCK_SIZE - 1);
			blocks = nbytes / AES_BLOCK_SIZE;
		} else {
			/* This is the last walk. We should handle the tail data. */
			blocks = DIV_ROUND_UP(nbytes, AES_BLOCK_SIZE);
		}
		ctr32 += blocks;

		kernel_vector_begin();
		/*
		 * The `if` block below detects the overflow, which is then handled by
		 * limiting the amount of blocks to the exact overflow point.
		 */
		if (ctr32 >= blocks) {
			rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
				walk.src.virt.addr, walk.dst.virt.addr, nbytes,
				ctx, req->iv);
		} else {
			/* use 2 ctr32 function calls for overflow case */
			current_blocks = blocks - ctr32;
			current_length =
				min(nbytes, current_blocks * AES_BLOCK_SIZE);
			rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
				walk.src.virt.addr, walk.dst.virt.addr,
				current_length, ctx, req->iv);
			crypto_inc(req->iv, 12);

			if (ctr32) {
				rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
					walk.src.virt.addr +
						current_blocks * AES_BLOCK_SIZE,
					walk.dst.virt.addr +
						current_blocks * AES_BLOCK_SIZE,
					nbytes - current_length, ctx, req->iv);
			}
		}
		kernel_vector_end();

		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
	}

	return err;
}

/* xts */
static int riscv64_xts_setkey(struct crypto_skcipher *tfm, const u8 *in_key,
			      unsigned int key_len)
{
	struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int xts_single_key_len = key_len / 2;
	int ret;

	ret = xts_verify_key(tfm, in_key, key_len);
	if (ret)
		return ret;
	ret = riscv64_aes_setkey_zvkned(&ctx->ctx1, in_key, xts_single_key_len);
	if (ret)
		return ret;
	return riscv64_aes_setkey_zvkned(
		&ctx->ctx2, in_key + xts_single_key_len, xts_single_key_len);
}

static int xts_crypt(struct skcipher_request *req, bool encrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_request sub_req;
	struct scatterlist sg_src[2], sg_dst[2];
	struct scatterlist *src, *dst;
	struct skcipher_walk walk;
	unsigned int walk_size = crypto_skcipher_alg(tfm)->walksize;
	unsigned int tail = req->cryptlen & (AES_BLOCK_SIZE - 1);
	unsigned int nbytes;
	unsigned int update_iv = 1;
	int err;

	/* xts input size should be bigger than AES_BLOCK_SIZE */
	if (req->cryptlen < AES_BLOCK_SIZE)
		return -EINVAL;

	riscv64_aes_encrypt_zvkned(&ctx->ctx2, req->iv, req->iv);

	if (unlikely(tail > 0 && req->cryptlen > walk_size)) {
		/*
		 * Find the largest tail size which is small than `walk` size while the
		 * non-ciphertext-stealing parts still fit AES block boundary.
		 */
		tail = walk_size + tail - AES_BLOCK_SIZE;

		skcipher_request_set_tfm(&sub_req, tfm);
		skcipher_request_set_callback(
			&sub_req, skcipher_request_flags(req), NULL, NULL);
		skcipher_request_set_crypt(&sub_req, req->src, req->dst,
					   req->cryptlen - tail, req->iv);
		req = &sub_req;
	} else {
		tail = 0;
	}

	err = skcipher_walk_virt(&walk, req, false);
	if (!walk.nbytes)
		return err;

	while ((nbytes = walk.nbytes)) {
		if (nbytes < walk.total)
			nbytes &= ~(AES_BLOCK_SIZE - 1);
		else
			update_iv = (tail > 0);

		kernel_vector_begin();
		if (encrypt)
			rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(
				walk.src.virt.addr, walk.dst.virt.addr, nbytes,
				&ctx->ctx1, req->iv, update_iv);
		else
			rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(
				walk.src.virt.addr, walk.dst.virt.addr, nbytes,
				&ctx->ctx1, req->iv, update_iv);
		kernel_vector_end();

		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
	}

	if (unlikely(tail > 0 && !err)) {
		dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
		if (req->dst != req->src)
			dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

		skcipher_request_set_crypt(req, src, dst, tail, req->iv);

		err = skcipher_walk_virt(&walk, req, false);
		if (err)
			return err;

		kernel_vector_begin();
		if (encrypt)
			rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(
				walk.src.virt.addr, walk.dst.virt.addr,
				walk.nbytes, &ctx->ctx1, req->iv, 0);
		else
			rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(
				walk.src.virt.addr, walk.dst.virt.addr,
				walk.nbytes, &ctx->ctx1, req->iv, 0);
		kernel_vector_end();

		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

static int riscv64_xts_encrypt(struct skcipher_request *req)
{
	return xts_crypt(req, true);
}

static int riscv64_xts_decrypt(struct skcipher_request *req)
{
	return xts_crypt(req, false);
}

static struct skcipher_alg riscv64_aes_algs_zvkned[] = {
	{
		.setkey = riscv64_aes_setkey,
		.encrypt = riscv64_ecb_encrypt,
		.decrypt = riscv64_ecb_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.walksize = AES_BLOCK_SIZE * 8,
		.base = {
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct crypto_aes_ctx),
			.cra_priority = 300,
			.cra_name	= "ecb(aes)",
			.cra_driver_name = "ecb-aes-riscv64-zvkned",
			.cra_module = THIS_MODULE,
		},
	}, {
		.setkey = riscv64_aes_setkey,
		.encrypt = riscv64_cbc_encrypt,
		.decrypt = riscv64_cbc_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.walksize = AES_BLOCK_SIZE * 8,
		.base = {
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct crypto_aes_ctx),
			.cra_priority = 300,
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc-aes-riscv64-zvkned",
			.cra_module = THIS_MODULE,
		},
	}
};

static struct skcipher_alg riscv64_aes_alg_zvkned_zvkb = {
	.setkey = riscv64_aes_setkey,
	.encrypt = riscv64_ctr_encrypt,
	.decrypt = riscv64_ctr_encrypt,
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
	.chunksize = AES_BLOCK_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.base = {
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct crypto_aes_ctx),
		.cra_priority = 300,
		.cra_name = "ctr(aes)",
		.cra_driver_name = "ctr-aes-riscv64-zvkned-zvkb",
		.cra_module = THIS_MODULE,
	},
};

static struct skcipher_alg riscv64_aes_alg_zvkned_zvbb_zvkg = {
	.setkey = riscv64_xts_setkey,
	.encrypt = riscv64_xts_encrypt,
	.decrypt = riscv64_xts_decrypt,
	.min_keysize = AES_MIN_KEY_SIZE * 2,
	.max_keysize = AES_MAX_KEY_SIZE * 2,
	.ivsize = AES_BLOCK_SIZE,
	.chunksize = AES_BLOCK_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.base = {
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_aes_xts_ctx),
		.cra_priority = 300,
		.cra_name = "xts(aes)",
		.cra_driver_name = "xts-aes-riscv64-zvkned-zvbb-zvkg",
		.cra_module = THIS_MODULE,
	},
};

static int __init riscv64_aes_block_mod_init(void)
{
	int ret = -ENODEV;

	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128 && riscv_vector_vlen() <= 2048) {
		ret = crypto_register_skciphers(
			riscv64_aes_algs_zvkned,
			ARRAY_SIZE(riscv64_aes_algs_zvkned));
		if (ret)
			return ret;

		if (riscv_isa_extension_available(NULL, ZVKB)) {
			ret = crypto_register_skcipher(&riscv64_aes_alg_zvkned_zvkb);
			if (ret)
				goto unregister_zvkned;
		}

		if (riscv_isa_extension_available(NULL, ZVBB) &&
		    riscv_isa_extension_available(NULL, ZVKG)) {
			ret = crypto_register_skcipher(&riscv64_aes_alg_zvkned_zvbb_zvkg);
			if (ret)
				goto unregister_zvkned_zvkb;
		}
	}

	return ret;

unregister_zvkned_zvkb:
	crypto_unregister_skcipher(&riscv64_aes_alg_zvkned_zvkb);
unregister_zvkned:
	crypto_unregister_skciphers(riscv64_aes_algs_zvkned,
				    ARRAY_SIZE(riscv64_aes_algs_zvkned));

	return ret;
}

static void __exit riscv64_aes_block_mod_fini(void)
{
	crypto_unregister_skcipher(&riscv64_aes_alg_zvkned_zvbb_zvkg);
	crypto_unregister_skcipher(&riscv64_aes_alg_zvkned_zvkb);
	crypto_unregister_skciphers(riscv64_aes_algs_zvkned,
				  ARRAY_SIZE(riscv64_aes_algs_zvkned));
}

module_init(riscv64_aes_block_mod_init);
module_exit(riscv64_aes_block_mod_fini);

MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS (RISC-V accelerated)");
MODULE_AUTHOR("Jerry Shih <jerry.shih@sifive.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("cbc(aes)");
MODULE_ALIAS_CRYPTO("ctr(aes)");
MODULE_ALIAS_CRYPTO("ecb(aes)");
MODULE_ALIAS_CRYPTO("xts(aes)");
