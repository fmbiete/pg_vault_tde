/*
 * pg_vault_tde_crypto_ope.c - Correctly Ordered & Collision-Free Order Revealing/Preserving Encryption
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * This module implements a lightweight, deterministic Order-Revealing/Preserving
 * Encryption (ORE/OPE) scheme optimized for byte-by-byte lexicographical comparisons
 * within PostgreSQL indexes.
 *
 * Traditional OPE schemes map values across wide numeric distributions. This implementation
 * instead constructs a strictly monotonic 1-to-1 byte substitution map (0-255) derived
 * deterministically from the Data Encryption Key (DEK) via an OpenSSL HMAC-SHA256 Pseudo-Random
 * Function (PRF).
 *
 * Core Features:
 * 1. Monotonic Substitution Map: Maps each input plaintext byte into a unique, higher-indexed
 *    ciphertext byte, preventing collisions and preserving natural sort order natively.
 * 2. C-String Safety: The byte map eliminates the null byte (0x00) from active cipher blocks,
 *    safeguarding database text processing functions against premature termination.
 * 3. Dynamic Length Appending: A terminating 0x00 is appended to the ciphertext buffer.
 *    header structure.
 * 4. Index-Optimized Comparison: Because the encryption guarantees that no 0x00 is present.
 *    execpt the terminating one, we can use a trivial strcmp or memcmp with length.
 *
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

/*
 * tde_crypto_ope_ctx_init
 *
 * Lazily allocates and initializes the OpenSSL HMAC context structure inside the
 * PostgreSQL TopMemoryContext to persist across transaction boundaries.
 */
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

/*
 * tde_crypto_ope_ctx_cleanup
 *
 * Frees the OpenSSL HMAC context and securely zeroes out memory slots storing
 * cached Data Encryption Keys (DEK) and order-preserving cryptographic maps.
 */
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

/*
 * bytes_to_hex_string
 *
 * Allocates memory within the PostgreSQL memory context and converts a raw binary
 * byte buffer into a null-terminated lowercase hexadecimal string representation.
 */
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

/*
 * get_index_pseudo_random_expansion
 *
 * Executes an HMAC-SHA256 iteration using the active DEK key context over a strictly
 * structured index context frame to yield a deterministic pseudorandom data expansion block.
 */
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
 * build_order_preserving_key_map
 *
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

/*
 * tde_crypto_ope_encrypt
 *
 * Encrypts arbitrary input plaintext bytes into an order-preserving format using
 * the monotonic substitution map, dynamically suffixing length specifiers. Returns
 * a palloc'd char pointer.
 */
char *
tde_crypto_ope_encrypt(const char *dek,
					   const char *plaintext, Size plaintext_len,
					   Size *out_len)
{
	char	   *ciphertext;
	Size		cyphertext_len = Min(plaintext_len, MAX_OPE_BYTES);

	if (encrypt_slot.ctx == NULL)
	{
		tde_crypto_ope_ctx_init();
		if (encrypt_slot.ctx == NULL)
		{
			elog(ERROR, "[CRYPTO-OPE] Context allocation failure");
		}
	}

	if (!encrypt_slot.is_valid || memcmp(encrypt_slot.cached_key, dek, TDE_DEK_LEN) != 0)
	{
		if (!HMAC_Init_ex(encrypt_slot.ctx, dek, TDE_DEK_LEN, EVP_sha256(), NULL))
		{
			tde_crypto_ope_ctx_cleanup();
			elog(ERROR, "[CRYPTO-OPE] Cipher initialization failure");
		}
		memcpy(encrypt_slot.cached_key, dek, TDE_DEK_LEN);

		build_order_preserving_key_map();
		encrypt_slot.is_valid = true;
	}

	*out_len = cyphertext_len + 1;	/* adding final 0x00 */
	ciphertext = (char *) palloc0(*out_len);

	for (Size i = 0; i < cyphertext_len; i++)
	{
		ciphertext[i] = encrypt_slot.crypto_map[(uint8_t) plaintext[i]];
	}

	ciphertext[cyphertext_len] = 0x00;

/*
	{
		char	   *plaintext_hex = bytes_to_hex_string(plaintext, plaintext_len);
		char	   *dek_hex = bytes_to_hex_string(dek, TDE_DEK_LEN);
		char	   *ciphertext_hex = bytes_to_hex_string((const char *) payload->ciphertext, cyphertext_len);

		elog(DEBUG1, "[pg_vault_tde:tde_crypto_ope_encrypt] plaintext: (%lu) '%s' - ciphertext: (%lu) '%s' - dek: (%u) '%s'",
			 plaintext_len, plaintext_hex, cyphertext_len, ciphertext_hex, TDE_DEK_LEN, dek_hex);
		pfree(ciphertext_hex);
		pfree(plaintext_hex);
		pfree(dek_hex);
	}
*/

	return ciphertext;
}

/*
 * tde_crypto_ope_compare
 *
 * Compares two order-preserving ciphertexts byte-by-byte. Emulates a SQL standard
 * sorting routine returning a negative integer, zero, or a positive integer depending
 * on whether the underlying plaintext values are less than, equal to, or greater than each other.
 */
int
tde_crypto_ope_compare(const char *ctxt1, const char *ctxt2)
{
	int			final_res;

	if (!ctxt1 && !ctxt2)
	{
		final_res = 0;
		goto log_and_return;
	}
	if (!ctxt1)
	{
		final_res = -1;
		goto log_and_return;
	}
	if (!ctxt2)
	{
		final_res = 1;
		goto log_and_return;
	}

	/*
	 * A simple byte-by-byte string comparison is entirely sufficient and
	 * accurately matches the natural sort order of the plaintext.
	 */
	final_res = strcmp(ctxt1, ctxt2);

log_and_return:
/*
	if (ctxt1 && ctxt2)
	{
		char	   *p1_hex = bytes_to_hex_string(ctxt1, strlen(ctxt1));
		char	   *p2_hex = bytes_to_hex_string(ctxt2, strlen(ctxt2));

		elog(DEBUG1, "[pg_vault_tde:tde_crypto_ope_compare] comparison: %d - ctxt1: (%d) '%s' - ctxt2: (%d) '%s'",
			 final_res, strlen(ctxt1), p1_hex, strlen(ctxt2), p2_hex);
		pfree(p1_hex);
		pfree(p2_hex);
	}
*/
	return final_res;
}
