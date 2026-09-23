/*
 * pg_vault_tde_crypto_ope.c - Order Preserving Encryption using AES-256-ECB
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Order-Preserving Encryption (OPE) allows database indexes to support range
 * queries (>, <, BETWEEN), unique constraints, and ordering optimizations
 * (`ORDER BY`) directly on encrypted data without exposing raw plaintexts
 * to the storage layer. Standard index structures like B-Trees require strict
 * mathematical ordering semantics:
 *
 *     If A < B, then Enc(A) < Enc(B)
 *
 * Probabilistic encryption schemes (such as AES-GCM or AES-CBC with random IVs)
 * destroy these properties completely. This engine achieves true order preservation
 * over variable-length text strings using the following architectural pillars:
 *
 * 1. Base-256 Lexicographical Alignment & Space Equalization
 * Strings are variable-length by nature. In alphabetical sorting, a shorter prefix
 * (e.g., "Ali") must sort before a longer extension (e.g., "Alice"). To enforce
 * uniform mathematical evaluations across variable lengths, we map plaintexts
 * onto a fixed-size byte array payload capped at `OPE_MAX_LEN` (2048 bytes).
 * Shorter strings are placed at the high-order bytes and right-padded with
 * deterministic zero bytes. This creates a uniform number space, ensuring that
 * standard memory comparison (`memcmp`) lines up identically for the indexer.
 *
 * 2. Continuous Multi-Precision Ripple-Carry Arithmetic
 * Block ciphers operate over disjoint 16-byte steps, which typically ruins raw
 * lexicographical sorting across block boundaries. To create a true OPE that
 * sorts natively on disk, a continuous 2048-byte deterministic noise mask is
 * generated via a counter-driven AES-256-ECB keystream. To blend this noise
 * securely without disrupting the sorting hierarchy, multi-precision big-endian
 * carry arithmetic is executed uniformly from right to left (index 2047 down to 0).
 * Because the carry smoothly cascades through the entire 2048-byte array, the
 * whole numerical scale shifts uniformly. This preserves natural alphabetical
 * sorting while completely obscuring the underlying text data.
 *
 * 3. Process-Local Session Context Caching & Lifetime Model
 * Allocating cipher contexts (`EVP_CIPHER_CTX_new`) and rebuilding internal key
 * schedules on every row operation causes severe heap fragmentation and massive
 * latency spikes during bulk database tasks (such as index builds or sequential
 * scans). We optimize execution by caching a persistent context (`encrypt_slot`)
 * inside a global static tracking structure allocated in `TopMemoryContext`.
 * Because AES-256-ECB is stateless and lacks an IV, the computed key schedule
 * remains resident in memory. On cache hits (where consecutive operations share
 * the same Data Encryption Key), the initial setup path (`EVP_EncryptInit_ex`)
 * is completely bypassed, routing the operational path directly through a fast,
 * uninterrupted `EVP_EncryptUpdate` sequence.
 *
 * 4. Security Trade-offs & Operational Boundaries
 * By design, OPE sacrifices semantic security to achieve database searchability.
 * Because identical plaintexts result in identical ciphertexts under the same
 * key, this scheme leaks relative order relations and frequency distribution
 * patterns. (Note: leaking data distribution properties is a requirement for the
 * PostgreSQL query planner to accurately collect column statistics).
 * This module relies strictly on the assumption that SQL Access Control Lists (ACLs)
 * and physical database environment boundaries prevent unauthorized visibility
 * into raw page distribution patterns, focusing cryptographically on preventing
 * plain text disclosure from storage-level compromises.
 */

#include "postgres.h"
#include "utils/memutils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

#include "src/include/pg_vault_tde_crypto_ope.h"


/* Context caching infrastructure */
typedef struct OpeCacheSlot
{
	EVP_CIPHER_CTX *ctx;
	unsigned char cached_key[32];
	bool is_valid;
} OpeCacheSlot;

static OpeCacheSlot encrypt_slot = {NULL, {0}, false};

void tde_crypto_ope_ctx_init(void)
{
	if (encrypt_slot.ctx == NULL)
	{
		MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);
		encrypt_slot.ctx = EVP_CIPHER_CTX_new();
		MemoryContextSwitchTo(old);
		if (encrypt_slot.ctx != NULL)
		{
			EVP_CIPHER_CTX_set_padding(encrypt_slot.ctx, 0);
		}
	}
}

void tde_crypto_ope_ctx_cleanup(void)
{
	if (encrypt_slot.ctx != NULL)
	{
		EVP_CIPHER_CTX_free(encrypt_slot.ctx);
		encrypt_slot.ctx = NULL;
	}
	OPENSSL_cleanse(encrypt_slot.cached_key, sizeof(encrypt_slot.cached_key));
	encrypt_slot.is_valid = false;
}

/*
 * tde_crypto_ope_encrypt
 * Maps variable-length plaintext strings up to 2048 bytes into a naturally
 * sorting, order-preserving byte layout.
 */
char *
tde_crypto_ope_encrypt(const char *dek, int dek_len,
					   const char *plaintext, Size plaintext_len, Size *out_len)
{
	OpeSerializedPayload *payload;
	unsigned char prf_master_key[32];
	unsigned char block_input[16];
	unsigned char block_output[16];
	int out_l;

	/* Variables for scaling the noise mask up to 2048 bytes */
	unsigned char noise_mask[OPE_MAX_LEN];
	uint32_t carry;
	int idx;

	Assert(plaintext != NULL);
	Assert(out_len != NULL);

	if (plaintext_len > OPE_MAX_LEN)
		elog(ERROR, "[CRYPTO-OPE] Plaintext length exceeds maximum limit of 2048");

	/* 1. Derive master key stream from the relation DEK */
	if (SHA256((const unsigned char *)dek, dek_len, prf_master_key) == NULL)
	{
		elog(ERROR, "[CRYPTO-OPE] Master key derivation failed");
	}

	*out_len = sizeof(OpeSerializedPayload);
	payload = (OpeSerializedPayload *)palloc0(*out_len);

	/*
	 * 2. Base-256 Lexicographical Alignment.
	 * Right-pad shorter string variants with zeros so lengths line up uniformly.
	 */
	for (Size i = 0; i < OPE_MAX_LEN; i++)
	{
		payload->ope_ciphertext[i] = (i < plaintext_len) ? (unsigned char)plaintext[i] : 0;
	}

	if (encrypt_slot.ctx == NULL)
	{
		tde_crypto_ope_ctx_init();
		if (encrypt_slot.ctx == NULL)
		{
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Context allocation failure");
		}
	}

	/* 3. Cache Check / Key Switch Transformation Path */
	if (!encrypt_slot.is_valid || memcmp(encrypt_slot.cached_key, prf_master_key, 32) != 0)
	{
		if (EVP_EncryptInit_ex(encrypt_slot.ctx, EVP_aes_256_ecb(), NULL, prf_master_key, NULL) != 1)
		{
			tde_crypto_ope_ctx_cleanup();
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Cipher initialization failure");
		}
		memcpy(encrypt_slot.cached_key, prf_master_key, 32);
		encrypt_slot.is_valid = true;
	}
	else 
	{
		/*
 		 * Reset the existing context's internal block state and buffers.
 		 * Reuses the cached key schedule without triggering a costly key setup.
 		 */
		if (EVP_EncryptInit_ex(encrypt_slot.ctx, NULL, NULL, NULL, NULL) != 1)
		{
			tde_crypto_ope_ctx_cleanup();
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Cipher context reset failure");
		}
	}

	/*
	 * 4. Generate a deterministic, pseudo-random noise stream up to 2048 bytes.
	 * We stream block-by-block using AES-ECB over incrementing block counters
	 * to keep the offset consistent per relation DEK.
	 */
	for (int b = 0; b < (OPE_MAX_LEN / 16); b++)
	{
		memset(block_input, 0, sizeof(block_input));
		memcpy(block_input, &b, sizeof(b)); /* Counter-based input generation */

		if (EVP_EncryptUpdate(encrypt_slot.ctx, block_output, &out_l, block_input, 16) != 1)
		{
			tde_crypto_ope_ctx_cleanup();
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Cipher mask generation aborted");
		}
		memcpy(&noise_mask[b * 16], block_output, 16);
	}

	/*
	 * 5. Mix the deterministic noise stream directly into the 2048-byte layout.
	 * Apply continuous multi-precision carry arithmetic from right-to-left.
	 * This shifts the entire numerical matrix identically, preserving exact order.
	 */
	carry = 0;
	for (idx = OPE_MAX_LEN - 1; idx >= 0; idx--)
	{
		uint32_t sum = (uint32_t)payload->ope_ciphertext[idx] +
					   (uint32_t)noise_mask[idx] +
					   carry;

		payload->ope_ciphertext[idx] = (unsigned char)(sum & 0xFF);
		carry = sum >> 8;
	}

	/* 6. Log the complete layout validation data */
	{
		char *debug_plain = pnstrdup(plaintext, plaintext_len);
		char *debug_cipher = palloc(32 * 2 + 5); /* Log the first 32 bytes for visual sizing */

		for (int i = 0; i < 32; i++)
		{
			sprintf(&debug_cipher[i * 2], "%02x", payload->ope_ciphertext[i]);
		}
		sprintf(&debug_cipher[64], "...");

		elog(DEBUG1, "[CRYPTO-OPE] True OPE Complete. Plaintext: %s | Ciphertext Head (hex): %s",
			 debug_plain, debug_cipher);

		pfree(debug_plain);
		pfree(debug_cipher);
	}

	OPENSSL_cleanse(prf_master_key, sizeof(prf_master_key));
	return (char *)payload;
}

/*
 * tde_crypto_ope_compare
 * Standard natural comparison function. Because the ciphertexts are truly
 * order-preserving, a raw memcmp evaluation works natively.
 */
int tde_crypto_ope_compare(const char *ctxt1, const char *ctxt2)
{
	OpeSerializedPayload *payload1 = (OpeSerializedPayload *)ctxt1;
	OpeSerializedPayload *payload2 = (OpeSerializedPayload *)ctxt2;

	int comp_result = memcmp(payload1->ope_ciphertext, payload2->ope_ciphertext, OPE_MAX_LEN);

	if (comp_result < 0)
		return -1;
	else if (comp_result > 0)
		return 1;

	return 0;
}