/* SPDX-License-Identifier: GPL-2.0 */

#ifndef AES_RISCV64_GLUE_H
#define AES_RISCV64_GLUE_H

#include <crypto/aes.h>
#include <linux/types.h>

int riscv64_aes_setkey_zvkned(struct crypto_aes_ctx *ctx, const u8 *key,
			      unsigned int keylen);

void riscv64_aes_encrypt_zvkned(const struct crypto_aes_ctx *ctx, u8 *dst,
				const u8 *src);

void riscv64_aes_decrypt_zvkned(const struct crypto_aes_ctx *ctx, u8 *dst,
				const u8 *src);

#endif /* AES_RISCV64_GLUE_H */
