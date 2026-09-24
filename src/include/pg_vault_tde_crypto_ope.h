/*
 * pg_vault_tde_crypto_ope.h - Order Preserving Encryption using AES-256-ECB
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 */
#ifndef PG_VAULT_TDE_CRYPTO_OPE_H
#define PG_VAULT_TDE_CRYPTO_OPE_H

#include "postgres.h"

/*
 * GNU Zero-length array adaptation inside an anonymous union.
 * Forces payload array offset to exactly 0 bytes while remaining compiler clean.
 */
typedef struct OpeDynamicPayload
{
	union
	{
		unsigned char first_byte;
		unsigned char ciphertext[0];
	};
}			OpeDynamicPayload;

void		tde_crypto_ope_ctx_init(void);
void		tde_crypto_ope_ctx_cleanup(void);

char	   *bytes_to_hex_string(const char *src, int len);

char	   *tde_crypto_ope_encrypt(const char *dek,
								   const char *plaintext, Size plaintext_len,
								   Size *out_len);

int			tde_crypto_ope_compare(const char *ctxt1, const char *ctxt2);

#endif							/* PG_VAULT_TDE_CRYPTO_OPE_H */
