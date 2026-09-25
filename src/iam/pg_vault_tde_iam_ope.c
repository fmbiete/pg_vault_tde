/*
 * pg_vault_tde_iam_ope.c - Order-Preserving Encryption (OPE) IAM handler
 *
 * Copyright (c) 2026 Francisco Miguel Biete Banon
 * Licensed under the PostgreSQL License.
 *
 * DESIGN RATIONALE:
 * -----------------
 * Deterministic encryption (such as AES-256-SIV in tde_btree) only preserves
 * equality, precluding range scans (<, <=, >, >=).
 *
 * This module implements the tde_ope_btree access method, which wraps native
 * B-Tree using Order-Preserving Encryption (OPE). Under OPE, encrypted index
 * tokens preserve order, allowing native B-Tree to evaluate both equality and
 * range scans.
 */
#include "postgres.h"
#include "access/amapi.h"
#include "access/genam.h"
#include "access/nbtree.h"
#include "access/tableam.h"		/* table_index_build_scan, IndexBuildCallback */
#include "nodes/execnodes.h"	/* IndexInfo full struct definition */
#include "utils/builtins.h"
#include "utils/fmgroids.h"		/* F_BTHANDLER */
#include "utils/memutils.h"
#include "utils/syscache.h"		/* SearchSysCache1, ReleaseSysCache, CLAOID */
#include "utils/uuid.h"			/* DatumGetUUIDP, pg_uuid_t */
#include "catalog/pg_opclass.h" /* Form_pg_opclass */
#include "catalog/pg_am_d.h"	/* BTREE_AM_OID */
#include "storage/lwlock.h"

#include <openssl/crypto.h>

#include "src/include/pg_vault_tde_catalog.h"
#include "src/include/pg_vault_tde_iam_ope.h"
#include "src/include/pg_vault_tde_kms.h"
#include "src/include/pg_vault_tde_crypto_ope.h"

/* Forward declaration of build function for identity checks. */
static IndexBuildResult *pg_vault_tde_ope_ambuild(Relation heap, Relation index,
												  IndexInfo *index_info);

/* Mutable copy of the btree AM routine, patched with our OPE overrides */
static IndexAmRoutine tde_ope_btree_methods;

/* Original (unmodified) btree AM — saved as a STATIC copy for safe delegation */
static IndexAmRoutine saved_btree_methods;
static bool saved_btree_methods_valid = false;

/*----------------------------- OPERATORS -----------------------------*/
/*
 * tde_iam_ope_bytea_cmp — B-Tree support function 1 (three-way comparator).
 * Evaluates the structural relative order of two ORE dynamic payload ciphertexts.
 */
PG_FUNCTION_INFO_V1(tde_iam_ope_bytea_cmp);
Datum
tde_iam_ope_bytea_cmp(PG_FUNCTION_ARGS)
{
	bytea	   *a = PG_GETARG_BYTEA_PP(0);
	bytea	   *b = PG_GETARG_BYTEA_PP(1);

	/* Extract direct pointers to the char * */
	const char *ctxt_a = (const char *) VARDATA_ANY(a);
	const char *ctxt_b = (const char *) VARDATA_ANY(b);

	int			result = tde_crypto_ope_compare(ctxt_a, ctxt_b);

	PG_RETURN_INT32(result);
}


/*
 * Macro template to generate a standard boolean operator wrapper.
 * This completely removes the copy-pasted DirectFunctionCall2 boilerplate.
 */
#define DEFINE_OPE_BOOL_OP(func_name, operator_macro)                        \
	PG_FUNCTION_INFO_V1(func_name);                                          \
	Datum                                                                    \
	func_name(PG_FUNCTION_ARGS)                                              \
	{                                                                        \
		int32 cmp = DatumGetInt32(DirectFunctionCall2(tde_iam_ope_bytea_cmp, \
													  PG_GETARG_DATUM(0),    \
													  PG_GETARG_DATUM(1)));  \
		PG_RETURN_BOOL(cmp operator_macro 0);                                \
	}

/* Generate all 5 core boolean operators cleanly */
DEFINE_OPE_BOOL_OP(tde_iam_ope_bytea_lt, <)
DEFINE_OPE_BOOL_OP(tde_iam_ope_bytea_le, <=)
DEFINE_OPE_BOOL_OP(tde_iam_ope_bytea_eq, ==)
DEFINE_OPE_BOOL_OP(tde_iam_ope_bytea_ge, >=)
DEFINE_OPE_BOOL_OP(tde_iam_ope_bytea_gt, >)

/*
 * Macro template to generate identical type-specific 3-way comparator wrappers.
 * Since they all just forward directly to tde_iam_ope_bytea_cmp, we can automate them.
 */
#define DEFINE_OPE_CMP_FORWARD(func_name)                                                          \
	PG_FUNCTION_INFO_V1(func_name);                                                                \
	Datum                                                                                          \
	func_name(PG_FUNCTION_ARGS)                                                                    \
	{                                                                                              \
		return DirectFunctionCall2(tde_iam_ope_bytea_cmp, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)); \
	}

/* Generate all typed 3-way comparator forwards */
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_text_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_bpchar_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_int4_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_int8_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_uuid_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_date_cmp)
DEFINE_OPE_CMP_FORWARD(tde_iam_ope_timestamptz_cmp)


/*
 * Check if the index relation is managed by tde_ope_btree by verifying that
 * the access method utilizes our customized build routine.
 */
bool
tde_iam_is_ope_btree_index(Relation index_rel)
{
	return index_rel->rd_indam != NULL &&
		index_rel->rd_indam->ambuild == pg_vault_tde_ope_ambuild;
}

/*
 * tde_iam_ope_serialize_fixed_type — serialize fixed-size primitive types
 * (INT4, DATE, INT8, TIMESTAMPTZ, UUID) to a canonical big-endian byte array,
 * applying sign-bit inversion where appropriate to maintain correct physical
 * sorting properties for signed numeric representations.
 */
static void
tde_iam_ope_serialize_fixed_type(Datum datum, Oid typoid, uint8 *buf)
{
	switch (typoid)
	{
		case INT4OID:
			{
				uint32		v = (uint32) DatumGetInt32(datum) ^ 0x80000000;

				v = pg_hton32(v);
				memcpy(buf, &v, 4);
				return;
			}
			break;
		case DATEOID:
			{
				uint32		v = pg_hton32((uint32) DatumGetInt32(datum));

				memcpy(buf, &v, 4);
				return;
			}
			break;
		case INT8OID:
			{
				uint64		v = (uint64) DatumGetInt64(datum) ^ 0x8000000000000000ULL;

				v = pg_hton64(v);
				memcpy(buf, &v, 8);
				return;
			}
			break;
		case TIMESTAMPTZOID:
			{
				uint64		v = pg_hton64((uint64) DatumGetInt64(datum));

				memcpy(buf, &v, 8);
			}
			break;
		case UUIDOID:
			{
				pg_uuid_t  *uid = DatumGetUUIDP(datum);

				memcpy(buf, uid->data, 16);
			}
			break;
		default:
			ereport(ERROR,
					(errmsg("[IAM-OPE] tde_iam_ope_serialize_fixed_type: "
							"unknown typoid %u, encryption not possible",
							typoid)));
			break;
	}
}

/*
 * tde_iam_ope_encrypt_fixed_type_datum — fetch the relation's Data Encryption Key (DEK),
 * canonicalize the fixed-size Datum, and pass it to the ORE cryptographic engine
 * to generate a dynamically allocated bytea ciphertext.
 */
Datum
tde_iam_ope_encrypt_fixed_type_datum(Relation index_rel, Datum datum, Oid typoid)
{
	uint8		plain_buf[32];
	Size		enc_len = 0;
	char	   *encrypted;
	bytea	   *enc_bytea = NULL;
	unsigned char dek[TDE_DEK_LEN];

	memset(plain_buf, 0, sizeof(plain_buf));

	tde_iam_ope_serialize_fixed_type(datum, typoid, plain_buf);

	if (!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
	{
		ereport(ERROR,
				(errmsg("[IAM-OPE] tde_iam_ope_encrypt_fixed_type_datum: "
						"DEK unavailable for index rel: %u",
						RelationGetRelid(index_rel))));
	}

	PG_TRY();
	{
		encrypted = tde_crypto_ope_encrypt((const char *) dek,
										   (const char *) plain_buf, 32,
										   &enc_len);
		OPENSSL_cleanse(plain_buf, sizeof(plain_buf));

		enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
		SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
		memcpy(VARDATA(enc_bytea), encrypted, enc_len);
		OPENSSL_cleanse(encrypted, enc_len);
		pfree(encrypted);
	}
	PG_CATCH();
	{
		OPENSSL_cleanse(plain_buf, sizeof(plain_buf));
		OPENSSL_cleanse(dek, sizeof(dek));
		PG_RE_THROW();
	}
	PG_END_TRY();

	OPENSSL_cleanse(dek, sizeof(dek));
	return PointerGetDatum(enc_bytea);
}

/*
 * tde_iam_ope_encrypt_index_datum — encrypt variable-length or non-primitive Datums.
 * Extracts raw binary payload lengths safely for BYTEAOID geometries, converts text
 * boundaries via standard strings, extracts the active DEK, and wraps the payload
 * inside an ORE-encrypted bytea container.
 */
Datum
tde_iam_ope_encrypt_index_datum(Relation index_rel, Datum datum, bool typbyval, int16 typlen)
{
	if (typlen != -1 && typlen != -2)
	{
		ereport(DEBUG2,
				(errmsg("[IAM-OPE] Skipping index key encryption for "
						"variable-size column without enc_ops (typlen=%d, typbyval=%s)",
						(int) typlen, typbyval ? "true" : "false")));
		return datum;
	}

	{
		char	   *to_free = NULL;
		char	   *plain;
		Size		plen;
		Size		enc_len = 0;
		char	   *encrypted;
		bytea	   *enc_bytea = NULL;
		unsigned char dek[TDE_DEK_LEN];

		/*
		 * Fetch the true data type OID of the column from the index
		 * description to see if we are dealing with standard text or a raw
		 * binary bytea block.
		 */
		Oid			opcintype = index_rel->rd_opcintype[0];

		/* Primary key index operator type */

		if (opcintype == BYTEAOID)
		{
			/*
			 * Safe Binary Extraction Path: Directly read variable payload
			 * dimensions from header metadata tags instead of relying on
			 * null-terminated string utilities like strlen.
			 */
			struct varlena *v = (struct varlena *) DatumGetPointer(datum);

			plain = VARDATA_ANY(v);
			plen = VARSIZE_ANY_EXHDR(v);
			to_free = NULL;		/* points directly inside index tuple memory
								 * workspace */
		}
		else if (typlen == -1)
		{
			/* Standard Text Extraction Path */
			plain = text_to_cstring((const text *) DatumGetPointer(datum));
			plen = strlen(plain) + 1;	/* add 1 for the trailing \0 */
			to_free = plain;	/* we need to pfree text_to_cstring */
		}
		else
		{
			plain = DatumGetCString(datum); /* cannot pfree pointer data maps */
			plen = strlen(plain) + 1;	/* add 1 for the trailing \0 */
		}

		if (!pg_vault_tde_kms_get_rel_dek(RelationGetRelid(index_rel), dek, sizeof(dek)))
		{
			ereport(ERROR,
					(errmsg("[IAM-OPE] tde_iam_ope_encrypt_index_datum: "
							"DEK unavailable for index relid %u",
							RelationGetRelid(index_rel))));
		}

		PG_TRY();
		{
			encrypted = tde_crypto_ope_encrypt((const char *) dek,
											   plain, plen,
											   &enc_len);

			enc_bytea = (bytea *) palloc(VARHDRSZ + enc_len);
			SET_VARSIZE(enc_bytea, VARHDRSZ + enc_len);
			memcpy(VARDATA(enc_bytea), encrypted, enc_len);
			OPENSSL_cleanse(encrypted, enc_len);
			pfree(encrypted);
		}
		PG_CATCH();
		{
			OPENSSL_cleanse(dek, sizeof(dek));
			PG_RE_THROW();
		}
		PG_END_TRY();

		if (to_free)
			pfree(to_free);
		OPENSSL_cleanse(dek, sizeof(dek));

		return PointerGetDatum(enc_bytea);
	}
}

/* ── B-TREE PROXY ACCESS METHOD IMPLEMENTATION ──────────────────────────── */

static inline void
tde_ope_assert_not_impersonated(Relation index)
{
	Assert(index->rd_rel->relam != BTREE_AM_OID);
}

/*
 * pg_vault_tde_ope_ambuild — proxy index builder. Temporarily patches the index
 * relation's amoid/relam identifier to mask as a standard BTREE_AM_OID, executes
 * the underlying native btree build routine, and safely restores the original AM identifier
 * during success or cleanup stack-unwinding.
 */
static IndexBuildResult *
pg_vault_tde_ope_ambuild(Relation heap, Relation index, IndexInfo *index_info)
{
	IndexBuildResult *result;
	Oid			saved_relam = index->rd_rel->relam;

	Assert(saved_btree_methods_valid);
	tde_ope_assert_not_impersonated(index);

	index->rd_rel->relam = BTREE_AM_OID;

	PG_TRY();
	{
		result = saved_btree_methods.ambuild(heap, index, index_info);
	}
	PG_CATCH();
	{
		index->rd_rel->relam = saved_relam;
		PG_RE_THROW();
	}
	PG_END_TRY();
	index->rd_rel->relam = saved_relam;

	return result;
}

/*
 * pg_vault_tde_ope_aminsert — proxy index tuple insertion interceptor. Intercepts incoming
 * raw Datums, routes them through type-specific ORE encryption handlers based on attribute
 * metadata, temporarily switches relam contexts to standard B-Tree, and delegates the
 * physical insertion to the native B-Tree engine.
 */
static bool
pg_vault_tde_ope_aminsert(Relation index, Datum *values, bool *isnull,
						  ItemPointer heap_tid, Relation heap,
						  IndexUniqueCheck check_unique,
						  bool index_unchanged,
						  IndexInfo *index_info)
{
	Datum		enc_values[INDEX_MAX_KEYS];
	bool		enc_isnull[INDEX_MAX_KEYS];
	int			ncols = index_info->ii_NumIndexAttrs;
	int			i;
	bool		result;
	Oid			saved_relam;

	Assert(saved_btree_methods_valid);
	tde_ope_assert_not_impersonated(index);

	memcpy(enc_isnull, isnull, ncols * sizeof(bool));

	for (i = 0; i < ncols; i++)
	{
		if (isnull[i])
		{
			enc_values[i] = (Datum) 0;
		}
		else
		{
			Oid			typoid = index->rd_opcintype[i];

			if (typoid == INT4OID || typoid == INT8OID ||
				typoid == DATEOID || typoid == TIMESTAMPTZOID ||
				typoid == UUIDOID)
			{
				enc_values[i] = tde_iam_ope_encrypt_fixed_type_datum(
																	 index,
																	 values[i],
																	 typoid);
			}
			else
			{
				Form_pg_attribute att = TupleDescAttr(index->rd_att, i);

				enc_values[i] = tde_iam_ope_encrypt_index_datum(
																index,
																values[i],
																att->attbyval,
																att->attlen);
			}
		}
	}

	saved_relam = index->rd_rel->relam;
	index->rd_rel->relam = BTREE_AM_OID;

	PG_TRY();
	{
		result = saved_btree_methods.aminsert(index, enc_values, enc_isnull,
											  heap_tid, heap,
											  check_unique, index_unchanged,
											  index_info);
	}
	PG_CATCH();
	{
		index->rd_rel->relam = saved_relam;
		PG_RE_THROW();
	}
	PG_END_TRY();

	index->rd_rel->relam = saved_relam;
	return result;
}

/*
 * pg_vault_tde_ope_ambeginscan — proxy scanner allocation. Forwards tracking allocations
 * directly to the native btree implementation table.
 */
static IndexScanDesc
pg_vault_tde_ope_ambeginscan(Relation index, int nkeys, int norderbys)
{
	tde_ope_assert_not_impersonated(index);
	Assert(saved_btree_methods_valid);
	return saved_btree_methods.ambeginscan(index, nkeys, norderbys);
}

/*
 * pg_vault_tde_ope_amrescan — proxy scan key processor. Intercepts query bounds constraints,
 * encrypts literal comparison arguments into ORE ciphertexts, overrides comparison support functions
 * (`sk_func`) with safe bytea operators for the 5 basic B-Tree strategies, and forwards the
 * modified keys to the native B-Tree driver.
 */
static void
pg_vault_tde_ope_amrescan(IndexScanDesc scan, ScanKey keys, int nkeys,
						  ScanKey orderbys, int norderbys)
{
	int			i;

	Assert(scan->indexRelation->rd_rel != NULL);
	tde_ope_assert_not_impersonated(scan->indexRelation);
	Assert(saved_btree_methods_valid);

	if (keys != NULL)
	{
		for (i = 0; i < nkeys; i++)
		{
			/*
			 * ONLY encrypt the query bounds argument data. Do not touch
			 * sk_func.
			 */
			if ((keys[i].sk_flags & SK_ISNULL) == 0 &&
				(keys[i].sk_strategy >= BTLessStrategyNumber &&
				 keys[i].sk_strategy <= BTGreaterStrategyNumber))
			{
				int			col = keys[i].sk_attno - 1;
				Oid			opcintype = scan->indexRelation->rd_opcintype[col];

				if (opcintype == INT4OID || opcintype == INT8OID ||
					opcintype == DATEOID || opcintype == TIMESTAMPTZOID ||
					opcintype == UUIDOID)
				{
					keys[i].sk_argument =
						tde_iam_ope_encrypt_fixed_type_datum(scan->indexRelation,
															 keys[i].sk_argument,
															 opcintype);

					/*
					 * Set the sk_func (boolean cmp function for rd_opcintype)
					 * to the bytea one
					 */
					switch (keys[i].sk_strategy)
					{
						case BTLessStrategyNumber:	/* 1: < */
							fmgr_info(F_BYTEALT, &keys[i].sk_func);
							break;
						case BTLessEqualStrategyNumber: /* 2: <= */
							fmgr_info(F_BYTEALE, &keys[i].sk_func);
							break;
						case BTEqualStrategyNumber: /* 3: = */
							fmgr_info(F_BYTEAEQ, &keys[i].sk_func);
							break;
						case BTGreaterEqualStrategyNumber:	/* 4: >= */
							fmgr_info(F_BYTEAGE, &keys[i].sk_func);
							break;
						case BTGreaterStrategyNumber:	/* 5: > */
							fmgr_info(F_BYTEAGT, &keys[i].sk_func);
							break;
						default:
							elog(ERROR, "[IAM-OPE] Unsupported B-Tree strategy number: %d",
								 keys[i].sk_strategy);
							break;
					}
				}
				else
				{
					Form_pg_attribute att = TupleDescAttr(scan->indexRelation->rd_att, col);

					keys[i].sk_argument =
						tde_iam_ope_encrypt_index_datum(scan->indexRelation,
														keys[i].sk_argument,
														att->attbyval,
														att->attlen);
				}
			}
		}
	}

	/* Forward cleanly to native btree. It will automatically load your custom */
	/* SQL-registered comparison handlers natively. */
	saved_btree_methods.amrescan(scan, keys, nkeys, orderbys, norderbys);
}

/*
 * pg_vault_tde_ope_amvalidate — proxy operator class validator. Extends standard index
 * AM verification constraints to natively allow encrypted operator classes containing cross-type
 * bytea structural storage signatures (`opckeytype` == BYTEAOID).
 */
static bool
pg_vault_tde_ope_amvalidate(Oid opclassoid)
{
	HeapTuple	classtup;
	Form_pg_opclass classform;
	bool		is_enc_ops;

	Assert(saved_btree_methods_valid);

	classtup = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclassoid));
	if (!HeapTupleIsValid(classtup))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("cache lookup failed for operator class %u", opclassoid)));

	classform = (Form_pg_opclass) GETSTRUCT(classtup);
	is_enc_ops = (OidIsValid(classform->opckeytype) &&
				  classform->opckeytype == BYTEAOID &&
				  classform->opcintype != BYTEAOID);
	ReleaseSysCache(classtup);

	if (is_enc_ops)
		return true;

	return saved_btree_methods.amvalidate(opclassoid);
}

/*
 * tde_ope_iam_init — system bootstrap hook for the OPE proxy access method.
 * Extracts native B-Tree handler callbacks, clones them into a mutable structure, overrides
 * structural interfaces (`ambuild`, `aminsert`, `amrescan`, `amvalidate`), sets AM storage flags,
 * and handles localized cryptographic module workspace contexts.
 */
void
tde_ope_iam_init(void)
{
	IndexAmRoutine *tmp = (IndexAmRoutine *) DatumGetPointer(
															 OidFunctionCall1(F_BTHANDLER, PointerGetDatum(NULL)));

	Assert(tmp != NULL);
	Assert(tmp->type == T_IndexAmRoutine);

	memcpy(&saved_btree_methods, tmp, sizeof(IndexAmRoutine));
	memcpy(&tde_ope_btree_methods, tmp, sizeof(IndexAmRoutine));

	pfree(tmp);
	saved_btree_methods_valid = true;

	tde_ope_btree_methods.ambuild = pg_vault_tde_ope_ambuild;
	tde_ope_btree_methods.aminsert = pg_vault_tde_ope_aminsert;
	tde_ope_btree_methods.ambeginscan = pg_vault_tde_ope_ambeginscan;
	tde_ope_btree_methods.amrescan = pg_vault_tde_ope_amrescan;
	tde_ope_btree_methods.amvalidate = pg_vault_tde_ope_amvalidate;
	tde_ope_btree_methods.amcanreturn = NULL;
	tde_ope_btree_methods.amcanbuildparallel = false;
	tde_ope_btree_methods.amstorage = true;

	tde_crypto_ope_ctx_init();

	ereport(DEBUG1,
			(errmsg("[IAM-OPE] tde_ope_btree initialized: btree AM wrapped with "
					"Order-Revealing Encryption layer")));
}

/*
 * Free per-backend ORE cryptographic context objects during backend shutdown or cleanup loops.
 */
void
tde_ope_iam_ctx_cleanup(void)
{
	tde_crypto_ope_ctx_cleanup();
}

/*
 * pg_vault_tde_get_iam_ope_routine — returns a dynamically allocated copy of our
 * customized OPE B-Tree IndexAmRoutine method table. Bootstraps the subsystem
 * automatically on first invocation.
 */
const IndexAmRoutine *
pg_vault_tde_get_iam_ope_routine(void)
{
	IndexAmRoutine *result;

	if (!saved_btree_methods_valid)
		tde_ope_iam_init();

	result = (IndexAmRoutine *) palloc(sizeof(IndexAmRoutine));
	memcpy(result, &tde_ope_btree_methods, sizeof(IndexAmRoutine));
	return result;
}
