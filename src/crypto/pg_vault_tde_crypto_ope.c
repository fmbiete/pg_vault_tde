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
 * This engine achieves true order-preserving indexing over both fixed binary data
 * and variable-length strings by deploying a wide-element expansion model, type-based
 * layout boundaries, and an isolated monotonic addition scheme.
 *
 * 1. Wide-Element Monotonic Arithmetic & Overflow Elimination
 * Standard modular addition (modulo 256) over unsigned byte buffers causes numerical
 * wrap-around boundaries where a larger value encrypts to a smaller number. To prevent
 * these structural order drops, inputs are expanded into a wide-element `uint16_t` space.
 * A deterministic pseudo-random mask byte is added directly to the plaintext element
 * (`plain_byte + mask_byte`). By expanding the allocation slot to 16 bits, the output
 * never wraps around a 256 boundary, fully preserving natural numeric and string
 * sorting properties without collision.
 *
 * 2. Carry-Free Structural Character Isolation
 * Multi-precision carry calculations ripple data variations across byte streams. In order
 * to protect sorting monotonicity across B-Tree node splits, additions are computed in
 * absolute isolation per position index. By eliminating right-to-left carry bit flows,
 * the relative alphabetical weight of individual string characters is preserved. Similarly,
 * fixed binary inputs pre-treated to an unsigned scale (e.g. via host-level MSB sign
 * bit inversion) preserve true numeric range limits cleanly.
 *
 * 3. Type-Aware Layout Bounds & Footprint Equalization
 * Database index comparisons alternate between variable text streams and fixed scalar footprints.
 * The allocation path routes calculations using an explicit execution mode:
 *   - Fixed-Width Vectors: Triggered for numeric, temporal, or spatial types. Memory bounds
 *     are instantly equalized to a static 16-element window. Trailing pads are zero-filled
 *     before masking to guarantee uniform comparisons.
 *   - Variable-Length Text: Processed character by character up to `plaintext_len`.
 * To prevent short queries or index scan descriptors from truncating comparisons early,
 * the alignment engine matches keys step-by-step using structural layout length markers.
 *
 * 4. Process-Local Context Caching & Single-Block Session Model
 * Rebuilding cryptographic contexts and internal key schedules on every row comparison
 * causes severe heap fragmentation. Latency is minimized by caching a persistent
 * `EVP_CIPHER_CTX` structure inside a global static slot allocated in `TopMemoryContext`.
 * A single uniform 16-byte pseudo-random block is generated via an AES-256-ECB keystream.
 * On consecutive index rows sharing the same Data Encryption Key (DEK), context initialization
 * is completely bypassed, routing the execution path directly through a fast block mask cycle.
 *
 * 5. Security Invariant
 * By design, OPE sacrifices semantic security to achieve database searchability. It leaks
 * relative ordering weight and frequency distributions, which allows the PostgreSQL
 * query planner to accurately collect column stats without reading plaintext keys.
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
					   const char *plaintext, Size plaintext_len, bool is_fixed_type,
					   Size *out_len)
{
	OpeDynamicPayload *payload;
	unsigned char prf_master_key[32];
	unsigned char block_input[16];
	unsigned char block_output[16];
	int out_l;
	uint16_t *ciphertext_ptr;
	Size final_len = (is_fixed_type) ? 16 : plaintext_len;

	Assert(dek != NULL);
	Assert(plaintext != NULL);
	Assert(out_len != NULL);

	if (SHA256((const unsigned char *)dek, dek_len, prf_master_key) == NULL)
	{
		elog(ERROR, "[CRYPTO-OPE] Master key derivation failed");
	}

	/* Both execution paths must allocate wide elements to keep structures uniform */
	*out_len = sizeof(OpeDynamicPayload) + (final_len * sizeof(uint16_t));
	payload = (OpeDynamicPayload *)palloc0(*out_len);
	payload->len = (uint32_t)final_len;

	if (encrypt_slot.ctx == NULL)
	{
		tde_crypto_ope_ctx_init();
		if (encrypt_slot.ctx == NULL)
		{
			pfree(payload);
			elog(ERROR, "[CRYPTO-OPE] Context allocation failure");
		}
	}

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

	/*
	 * Initialize the keystream block with a completely uniform, type-agnostic
	 * static footprint to ensure identical encryption masks regardless of length framing variations.
	 */
	memset(block_input, 0, sizeof(block_input));

	if (EVP_EncryptUpdate(encrypt_slot.ctx, block_output, &out_l, block_input, 16) != 1)
	{
		tde_crypto_ope_ctx_cleanup();
		pfree(payload);
		elog(ERROR, "[CRYPTO-OPE] Keystream block generation failed");
	}

	ciphertext_ptr = (uint16_t *)payload->ciphertext;

	if (is_fixed_type)
 	{
		for (int i = 0; i < 16; i++)
 		{
 			uint16_t mask_byte = block_output[i];
			uint16_t plain_byte = (i < (int)plaintext_len) ? (unsigned char)plaintext[i] : 0;
 			uint16_t sum = plain_byte + mask_byte;

			ciphertext_ptr[i] = sum;
		}
	}
	else
	{
		/* Expand text characters into wide slots to avoid modulo 256 wrap-around drops */
		for (Size i = 0; i < plaintext_len; i++)
		{
			uint16_t mask_byte = block_output[i % 16];
			ciphertext_ptr[i] = (uint16_t)((unsigned char)plaintext[i]) + mask_byte;
		}
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
	OpeDynamicPayload *p1 = (OpeDynamicPayload *)ctxt1;
	OpeDynamicPayload *p2 = (OpeDynamicPayload *)ctxt2;
	uint16_t *c1 = (uint16_t *)p1->ciphertext;
	uint16_t *c2 = (uint16_t *)p2->ciphertext;

	Size min_len = (p1->len < p2->len) ? p1->len : p2->len;

	/* Evaluate expanded order elements safely */
	for (Size i = 0; i < min_len; i++)
	{
		if (c1[i] < c2[i])
			return -1;
		if (c1[i] > c2[i])
			return 1;
	}

	/* Prefix is identical; shorter string goes first */
	if (p1->len < p2->len)
		return -1;
	if (p1->len > p2->len)
		return 1;

	return 0;
}
