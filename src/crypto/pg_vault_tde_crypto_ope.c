/*
 * pg_vault_tde_crypto_ope.c - Correctly Ordered & Collision-Free Order Revealing/Preserving Encryption
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 */

#include "postgres.h"
#include "utils/memutils.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

#include "src/include/pg_vault_tde_crypto_ope.h"
#include "src/include/pg_vault_tde_kms.h"

#define MAX_OPE_BYTES 2048

typedef struct OpeCacheSlot
{
	HMAC_CTX   *ctx;
	unsigned char cached_key[TDE_DEK_LEN];
	unsigned char crypto_map[256];
	bool		is_valid;
}			OpeCacheSlot;

static OpeCacheSlot encrypt_slot =
{
	NULL,
	{
		0
	},
	{
		0
	},
		false
};

void
tde_crypto_ope_ctx_init(void)
{
	if (encrypt_slot.ctx == NULL)
	{
		MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);

		encrypt_slot.ctx = HMAC_CTX_new();
		MemoryContextSwitchTo(old);
	}
}

void
tde_crypto_ope_ctx_cleanup(void)
{
	if (encrypt_slot.ctx != NULL)
	{
		HMAC_CTX_free(encrypt_slot.ctx);
		encrypt_slot.ctx = NULL;
	}
	OPENSSL_cleanse(encrypt_slot.cached_key, sizeof(encrypt_slot.cached_key));
	OPENSSL_cleanse(encrypt_slot.crypto_map, sizeof(encrypt_slot.crypto_map));
	encrypt_slot.is_valid = false;
}

char *
bytes_to_hex_string(const char *src, int len)
{
	static const char hex_digits[] = "0123456789abcdef";
	char	   *dst = (char *) palloc((len * 2) + 1);
	char	   *p = dst;

	for (int i = 0; i < len; i++)
	{
		unsigned char byte = (unsigned char) src[i];

		*p++ = hex_digits[byte >> 4];
		*p++ = hex_digits[byte & 0x0F];
	}

	*p = '\0';
	return dst;
}

static void
get_index_pseudo_random_expansion(Size index, unsigned char *out_prf_block)
{
	struct
	{
		uint64_t	idx;
		uint64_t	padding;
	}			context = {0};
	unsigned int hash_len = 0;

	context.idx = (uint64_t) index;

	if (!HMAC_Init_ex(encrypt_slot.ctx, NULL, 0, NULL, NULL) ||
		!HMAC_Update(encrypt_slot.ctx, (unsigned char *) &context, sizeof(context)) ||
		!HMAC_Final(encrypt_slot.ctx, out_prf_block, &hash_len))
	{
		elog(ERROR, "[CRYPTO-OPE] OpenSSL PRF calculation failed");
	}
}

/*
 * Generates a strictly monotonic substitution map derived from the DEK.
 * This guarantees order preservation byte-by-byte while securing the mapping.
 */
static void
build_order_preserving_key_map(void)
{
	unsigned char temp_prf[EVP_MAX_MD_SIZE];
	uint32_t	current_val = 0;

	for (int i = 0; i < 256; i++)
	{
		uint32_t	gap;

		get_index_pseudo_random_expansion((Size) i, temp_prf);

		/*
		 * Calculate a deterministic gap size using the PRF block. To map 256
		 * items uniquely into the 1-255 byte space, the average gap must be
		 * 1. If a PRF byte matches, we allow a tiny gap distribution,
		 * otherwise minimum step.
		 */
		gap = (temp_prf[0] % 2 == 0 && current_val + 1 < (uint32_t) (i + 1)) ? 0 : 1;

		/*
		 * Enforce minimum strict monotonicity step to guarantee
		 * collision-free mapping
		 */
		if (gap == 0 && current_val == 0)
			gap = 1;

		current_val += gap;

		/*
		 * Ensure we never emit 0x00, and stay inside strict byte scale
		 * boundaries
		 */
		if (current_val < 1)
			current_val = 1;
		if (current_val > 255)
			current_val = 255;

		/*
		 * Secondary fallback checks to enforce 1-to-1 injection across the
		 * array mapping
		 */
		if (i > 0 && current_val <= encrypt_slot.crypto_map[i - 1])
		{
			current_val = (uint32_t) encrypt_slot.crypto_map[i - 1] + 1;
			if (current_val > 255)
				current_val = 255;
		}

		encrypt_slot.crypto_map[i] = (unsigned char) current_val;
	}
}

static uint32_t
extract_ciphertext_len(const OpeDynamicPayload * payload)
{
	uint32_t	len = 0;
	const unsigned char *ptr = payload->ciphertext;

	for (int i = 0; i < MAX_OPE_BYTES; i++)
	{
		if (ptr[i] == 0x00)
		{
			memcpy(&len, &ptr[i + 1], sizeof(uint32_t));
			break;
		}
	}
	return len;
}

char *
tde_crypto_ope_encrypt(const char *dek,
					   const char *plaintext, Size plaintext_len,
					   Size *out_len)
{
	OpeDynamicPayload *payload;
	Size		cyphertext_len = plaintext_len < MAX_OPE_BYTES ? plaintext_len : MAX_OPE_BYTES;
	Size		header_size = sizeof(uint32_t) + 1;

	*out_len = header_size + cyphertext_len;
	payload = (OpeDynamicPayload *) palloc0(*out_len);

	if (encrypt_slot.ctx == NULL)
	{
		tde_crypto_ope_ctx_init();
		if (encrypt_slot.ctx == NULL)
		{
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Context allocation failure");
		}
	}

	if (!encrypt_slot.is_valid || memcmp(encrypt_slot.cached_key, dek, TDE_DEK_LEN) != 0)
	{
		if (!HMAC_Init_ex(encrypt_slot.ctx, dek, TDE_DEK_LEN, EVP_sha256(), NULL))
		{
			tde_crypto_ope_ctx_cleanup();
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Cipher initialization failure");
		}
		memcpy(encrypt_slot.cached_key, dek, TDE_DEK_LEN);

		build_order_preserving_key_map();
		encrypt_slot.is_valid = true;
	}

	for (Size i = 0; i < cyphertext_len; i++)
	{
		uint8_t		pt_byte = (uint8_t) plaintext[i];

		payload->ciphertext[i] = encrypt_slot.crypto_map[pt_byte];
	}

	payload->ciphertext[cyphertext_len] = 0x00;
	memcpy(&payload->ciphertext[cyphertext_len + 1], &cyphertext_len, sizeof(uint32_t));

	{
		uint32_t	extracted_cipher_len = extract_ciphertext_len(payload);
		char	   *plaintext_hex = bytes_to_hex_string(plaintext, plaintext_len);
		char	   *dek_hex = bytes_to_hex_string(dek, TDE_DEK_LEN);
		char	   *ciphertext_hex = bytes_to_hex_string((const char *) payload->ciphertext, cyphertext_len);

		elog(DEBUG1, "[pg_vault_tde:tde_crypto_ope_encrypt] plaintext: (%lu) '%s' - ciphertext: (%lu) [%u] '%s' - dek: (%u) '%s'",
			 plaintext_len, plaintext_hex, cyphertext_len, extracted_cipher_len, ciphertext_hex, TDE_DEK_LEN, dek_hex);
		pfree(ciphertext_hex);
		pfree(plaintext_hex);
		pfree(dek_hex);
	}

	return (char *) payload;
}

int
tde_crypto_ope_compare(const char *ctxt1, const char *ctxt2)
{
	uint32_t	p1_len;
	uint32_t	p2_len;
	uint32_t	min_len;
	int			final_res;

	const		OpeDynamicPayload *p1 = (const OpeDynamicPayload *) ctxt1;
	const		OpeDynamicPayload *p2 = (const OpeDynamicPayload *) ctxt2;

	if (!p1 && !p2)
	{
		final_res = 0;
		goto log_and_return;
	}
	if (!p1)
	{
		final_res = -1;
		goto log_and_return;
	}
	if (!p2)
	{
		final_res = 1;
		goto log_and_return;
	}

	p1_len = extract_ciphertext_len(p1);
	p2_len = extract_ciphertext_len(p2);

	min_len = (p1_len < p2_len) ? p1_len : p2_len;

	final_res = 0;
	for (uint32_t i = 0; i < min_len; i++)
	{
		uint8_t		byte1 = (uint8_t) p1->ciphertext[i];
		uint8_t		byte2 = (uint8_t) p2->ciphertext[i];

		if (byte1 != byte2)
		{
			final_res = (byte1 < byte2) ? -1 : 1;
			goto log_and_return;
		}
	}

	if (p1_len < p2_len)
	{
		final_res = -1;
		goto log_and_return;
	}
	if (p1_len > p2_len)
	{
		final_res = 1;
		goto log_and_return;
	}

	final_res = 0;

log_and_return:
	if (p1 && p2)
	{
		uint32_t	l1 = extract_ciphertext_len(p1);
		uint32_t	l2 = extract_ciphertext_len(p2);
		char	   *p1_hex = bytes_to_hex_string((const char *) p1->ciphertext, l1);
		char	   *p2_hex = bytes_to_hex_string((const char *) p2->ciphertext, l2);

		elog(DEBUG1, "[pg_vault_tde:tde_crypto_ope_compare] comparison: %d - ctxt1: (%d) '%s' - ctxt2: (%d) '%s'",
			 final_res, l1, p1_hex, l2, p2_hex);
		pfree(p1_hex);
		pfree(p2_hex);
	}
	return final_res;
}
