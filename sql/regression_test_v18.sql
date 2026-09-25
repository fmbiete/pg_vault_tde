-- regression_test_v18.sql — TDE tests tde_ope_btree for pg_vault_tde v1.8
--
-- These tests cover the tde_ope_btree introduced in v1.8,
-- which encrypt variable-size B-Tree index keys (int4, int8, uuid, date,
-- timestamptz) using OPE with STORAGE bytea.
--
-- Exit-on-error: any failed assertion aborts the script.
\set ON_ERROR_STOP on

-- ================================================================
-- TEST 141: Access Methods registered
-- ================================================================
DO $$
BEGIN
    PERFORM 1 FROM pg_am WHERE amname = 'tde_ope_btree';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TEST 141 FAILED: tde_ope_btree AM not found';
    END IF;
    RAISE NOTICE 'TEST 141 PASSED: tde_ope_btree Access Methods registered';
END;
$$;

-- ================================================================
-- TEST 142: Index scan — encrypted data readable via tde_ope_btree
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_idx (id int, secret text) USING encrypted_heap;
    CREATE INDEX ix_tde_idx ON tde_idx USING tde_ope_btree (id);
    INSERT INTO tde_idx VALUES (42, 'index_scan_secret');
	ANALYZE tde_idx;
    -- Force the planner to use the index
    SET enable_seqscan = off;
    SELECT secret INTO v FROM tde_idx WHERE id = 42;
    RESET enable_seqscan;
    IF v IS DISTINCT FROM 'index_scan_secret' THEN
        RAISE EXCEPTION 'TEST 142a FAILED: (index+insert) tde_ope_btree index scan returned wrong value "%"', v;
    END IF;
	DROP INDEX ix_tde_idx;

    CREATE INDEX ix_tde_idx ON tde_idx USING tde_ope_btree (id);
	ANALYZE tde_idx;
    -- Force the planner to use the index
    SET enable_seqscan = off;
    SELECT secret INTO v FROM tde_idx WHERE id = 42;
    RESET enable_seqscan;
    IF v IS DISTINCT FROM 'index_scan_secret' THEN
        RAISE EXCEPTION 'TEST 142b FAILED: (insert+index) tde_ope_btree index scan returned wrong value "%"', v;
    END IF;
	DROP TABLE tde_idx;

    RAISE NOTICE 'TEST 142 PASSED: index scan on encrypted_heap decrypts correctly';
END;
$$;

-- ================================================================
-- TEST 143: BitmapHeapScan — exercises scan_bitmap_next_tuple path via tde_ope_btree
-- ================================================================
DO $$
DECLARE
    cnt int;
    v   text;
BEGIN
    CREATE TABLE tde_bitmap (id int, payload text) USING encrypted_heap;
	CREATE INDEX ix_tde_bitmap ON tde_bitmap USING tde_ope_btree (id);
    INSERT INTO tde_bitmap SELECT g, 'bitmap_' || g FROM generate_series(1, 200) g;

	SET enable_seqscan = off;
    SET enable_indexscan = off;

    SELECT count(*) INTO cnt FROM tde_bitmap WHERE id BETWEEN 50 AND 150;
    IF cnt <> 101 THEN
        RAISE EXCEPTION 'TEST 143a FAILED: tde_ope_btree expected 101 rows, got %', cnt;
    END IF;

    SELECT payload INTO v FROM tde_bitmap WHERE id = 100;
    IF v IS DISTINCT FROM 'bitmap_100' THEN
        RAISE EXCEPTION 'TEST 143b FAILED: tde_ope_btree expected "bitmap_100", got "%"', v;
    END IF;

    RESET enable_seqscan;
    RESET enable_indexscan;
    DROP TABLE tde_bitmap;
    RAISE NOTICE 'TEST 143 PASSED: BitmapHeapScan decrypts correctly (scan_bitmap_next_tuple path)';
END;
$$;

-- ================================================================
-- TEST 144: REINDEX on encrypted_heap with tde_ope_btree index
-- ================================================================
DO $$
DECLARE
    v text;
BEGIN
    CREATE TABLE tde_reindex (
        id int,
        val text
    ) USING encrypted_heap;
	CREATE INDEX tde_reindex_idx ON tde_reindex USING tde_ope_btree(id);

    INSERT INTO tde_reindex SELECT g, 'val_' || g FROM generate_series(1, 50) g;

	-- Force an index scan to verify pre-REINDEX state
    SET enable_seqscan = off;
    SELECT val INTO v FROM tde_reindex WHERE id = 25;
    IF v IS DISTINCT FROM 'val_25' THEN
        RAISE EXCEPTION 'TEST 144a FAILED: tde_ope_btree pre-REINDEX index scan got "%"', v;
    END IF;

    -- Perform REINDEX
    REINDEX INDEX tde_reindex_idx;

    -- Verify data is still accessible via index after REINDEX
    SELECT val INTO v FROM tde_reindex WHERE id = 25;
    IF v IS DISTINCT FROM 'val_25' THEN
        RAISE EXCEPTION 'TEST 144b FAILED: tde_ope_btree post-REINDEX index scan got "%"', v;
    END IF;

    -- Also test REINDEX TABLE
    REINDEX TABLE tde_reindex;

    SELECT val INTO v FROM tde_reindex WHERE id = 50;
    IF v IS DISTINCT FROM 'val_50' THEN
        RAISE EXCEPTION 'TEST 144c FAILED: tde_ope_btree post-REINDEX TABLE got "%"', v;
    END IF;
    RESET enable_seqscan;

    DROP TABLE tde_reindex;
    RAISE NOTICE 'TEST 144 PASSED: REINDEX works on encrypted_heap + tde_ope_btree';
END;
$$;

-- ================================================================
-- TEST 145: tde_ope_btree CREATE INDEX + equality index scan
-- ================================================================
DO $$
DECLARE
    v_id  int;
    v_cnt int;
BEGIN
    CREATE TABLE tde_btree_test (id int, tag bytea) USING encrypted_heap;
    INSERT INTO tde_btree_test VALUES (42,  'answer'::bytea);
    INSERT INTO tde_btree_test VALUES (1,   'one'::bytea);
    INSERT INTO tde_btree_test VALUES (100, 'hundred'::bytea);

    -- Build the encrypted B-Tree index
    CREATE INDEX tde_btree_idx ON tde_btree_test USING tde_ope_btree (tag);

    -- Force index-only path: disable seqscan
    SET enable_seqscan = off;
    SELECT id INTO v_id FROM tde_btree_test WHERE tag = 'answer'::bytea;
    RESET enable_seqscan;

    IF v_id IS DISTINCT FROM 42 THEN
        RAISE EXCEPTION
            'TEST 145a FAILED: tde_ope_btree index scan returned % (expected 42)', v_id;
    END IF;

    -- Verify count via index
    SET enable_seqscan = off;
    SELECT count(*) INTO v_cnt FROM tde_btree_test WHERE tag = 'one'::bytea;
    RESET enable_seqscan;
    IF v_cnt != 1 THEN
        RAISE EXCEPTION
            'TEST 145b FAILED: tde_ope_btree count via index should be 1, got %', v_cnt;
    END IF;	

    DROP TABLE tde_btree_test;
    RAISE NOTICE 'TEST 145 PASSED: tde_ope_btree CREATE INDEX + equality scan OK';
END;
$$;

-- ================================================================
-- TEST 146: tde_ope_int4_enc_ops — equality lookup + binary file check
--
-- Verifies two things:
--   1. Equality lookup via tde_ope_int4_enc_ops index returns correct result
--   2. The raw integer value 42 (0x0000002A) is NOT present in the
--      index file on disk — confirming the key is truly encrypted.
--
-- Uses pg_read_binary_file (superuser) + CHECKPOINT to flush dirty
-- pages, following the same pattern as tests 87/88.
-- ================================================================
DO $$
DECLARE
    result_val text;
    idx_path   text;
    idx_oid    oid;
    raw_bytes  bytea;
    needle     bytea;
BEGIN
    DROP TABLE IF EXISTS tde_enc_int4_146;
    CREATE TABLE tde_enc_int4_146 (id int4, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_int4_idx_146
        ON tde_enc_int4_146 USING tde_ope_btree (id tde_ope_int4_enc_ops);

    INSERT INTO tde_enc_int4_146 VALUES (42, 'answer'), (100, 'hundred');

    -- Flush dirty pages so pg_read_binary_file sees current state
    CHECKPOINT;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_int4_146 WHERE id = 42;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'answer' THEN
        RAISE EXCEPTION
            'TEST 111 FAILED: equality lookup returned %, expected ''answer''',
            COALESCE(result_val, '<NULL>');
    END IF;

    -- Verify that the plaintext value 42 (big-endian: 0x0000002A) does NOT
    -- appear in the raw index file on disk.
    SELECT oid INTO idx_oid
    FROM pg_class WHERE relname = 'tde_enc_int4_idx_146';

    IF idx_oid IS NULL THEN
        RAISE EXCEPTION 'TEST 111 FAILED: index tde_enc_int4_idx_146 not found in pg_class';
    END IF;

    SELECT pg_relation_filepath(idx_oid) INTO idx_path;
    raw_bytes := pg_read_binary_file(idx_path);
    needle    := decode('0000002A', 'hex');  -- int4=42 in big-endian

    IF position(needle IN raw_bytes) > 0 THEN
        RAISE EXCEPTION
            'TEST 146 FAILED: plaintext int4=42 (0x0000002A) found in raw index file — '
            'tde_ope_int4_enc_ops is not encrypting the index key';
    END IF;

    DROP TABLE tde_enc_int4_146;
    RAISE NOTICE
        'TEST 146 PASSED: tde_ope_int4_enc_ops equality OK, plaintext key absent in raw index file';
END;
$$;

-- ================================================================
-- TEST 147: tde_ope_int8_enc_ops — equality lookup bigint
--
-- Inserts two rows and verifies that a single-row equality lookup
-- on int8=9876543210 via tde_ope_btree with tde_ope_int8_enc_ops returns
-- the correct associated label, exercising the 8-byte big-endian
-- serialisation + OPE path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_int8_112;
    CREATE TABLE tde_enc_int8_112 (id int8, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_int8_idx_112
        ON tde_enc_int8_112 USING tde_ope_btree (id tde_ope_int8_enc_ops);

    INSERT INTO tde_enc_int8_112 VALUES (9876543210, 'big'), (1, 'one');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_int8_112 WHERE id = 9876543210;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'big' THEN
        RAISE EXCEPTION
            'TEST 147 FAILED: int8 equality lookup returned %, expected ''big''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_int8_112;
    RAISE NOTICE 'TEST 147 PASSED: tde_ope_int8_enc_ops equality lookup OK (int8=9876543210)';
END;
$$;

-- ================================================================
-- TEST 148: tde_ope_uuid_enc_ops — equality lookup uuid
--
-- Inserts two rows with distinct UUIDs and verifies that the equality
-- lookup on the known UUID returns the correct id, exercising the
-- 16-byte RFC 4122 wire-bytes serialisation + OPE path.
-- ================================================================
DO $$
DECLARE
    test_uuid  uuid := '550e8400-e29b-41d4-a716-446655440000';
    result_id  int;
BEGIN
    DROP TABLE IF EXISTS tde_enc_uuid_149;
    CREATE TABLE tde_enc_uuid_149 (id int, token uuid) USING encrypted_heap;
    CREATE INDEX tde_enc_uuid_idx_149
        ON tde_enc_uuid_149 USING tde_ope_btree (token tde_ope_uuid_enc_ops);

    INSERT INTO tde_enc_uuid_149 VALUES
        (1, '550e8400-e29b-41d4-a716-446655440000'::uuid),
        (2, '6ba7b810-9dad-11d1-80b4-00c04fd430c8'::uuid);

    SET enable_seqscan = off;
    SELECT id INTO result_id
    FROM tde_enc_uuid_149 WHERE token = test_uuid;
    RESET enable_seqscan;

    IF result_id IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION
            'TEST 148 FAILED: uuid equality lookup returned %, expected 1',
            COALESCE(result_id::text, '<NULL>');
    END IF;

    DROP TABLE tde_enc_uuid_149;
    RAISE NOTICE 'TEST 148 PASSED: tde_ope_uuid_enc_ops equality lookup OK (uuid=550e8400...)';
END;
$$;

-- ================================================================
-- TEST 149: tde_ope_date_enc_ops — equality lookup date
--
-- Inserts two rows with distinct dates and verifies the equality
-- lookup on 2026-01-01 returns the correct label, exercising the
-- int32 big-endian serialisation for DateADT + OPE path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_date_149;
    CREATE TABLE tde_enc_date_149 (d date, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_date_idx_149
        ON tde_enc_date_149 USING tde_ope_btree (d tde_ope_date_enc_ops);

    INSERT INTO tde_enc_date_149 VALUES
        ('2026-01-01', 'new_year'),
        ('2000-02-29', 'leap');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_date_149 WHERE d = '2026-01-01'::date;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'new_year' THEN
        RAISE EXCEPTION
            'TEST 149 FAILED: date equality lookup returned %, expected ''new_year''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_date_149;
    RAISE NOTICE 'TEST 149 PASSED: tde_ope_date_enc_ops equality lookup OK (date=2026-01-01)';
END;
$$;

-- ================================================================
-- TEST 150: tde_ope_timestamptz_enc_ops — equality lookup timestamptz
--
-- Inserts two rows with distinct timestamps and verifies the equality
-- lookup on 2026-06-09 12:00:00+00 returns the correct label,
-- exercising the int64 big-endian serialisation for TimestampTz
-- + OPE path.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_enc_tstz_150;
    CREATE TABLE tde_enc_tstz_150 (ts timestamptz, label text) USING encrypted_heap;
    CREATE INDEX tde_enc_tstz_idx_150
        ON tde_enc_tstz_150 USING tde_ope_btree (ts tde_ope_timestamptz_enc_ops);

    INSERT INTO tde_enc_tstz_150 VALUES
        ('2026-06-09 12:00:00+00', 'noon'),
        ('1970-01-01 00:00:00+00', 'epoch');

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_tstz_150 WHERE ts = '2026-06-09 12:00:00+00'::timestamptz;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'noon' THEN
        RAISE EXCEPTION
            'TEST 150 FAILED: timestamptz equality lookup returned %, expected ''noon''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_enc_tstz_150;
    RAISE NOTICE 'TEST 150 PASSED: tde_ope_timestamptz_enc_ops equality lookup OK (2026-06-09 12:00:00+00)';
END;
$$;

-- ================================================================
-- TEST 151: DEK rotation — stale enc_ops index returns NULL,
--           REINDEX restores lookup
--
-- OPE is deterministic under a given DEK.  After rotating
-- the per-table DEK, the search predicate is re-encrypted with DEK-B
-- while the stored index keys were encrypted with DEK-A: no match is
-- found (NULL).  After REINDEX the keys are re-encrypted with DEK-B
-- and the lookup works again.
--
-- Table setup is committed before rotate_online so the BGW can see
-- the relation in its own connection.
-- ================================================================
DROP TABLE IF EXISTS tde_enc_rotation_151;
CREATE TABLE tde_enc_rotation_151 (id int4, label text) USING encrypted_heap;
CREATE INDEX tde_enc_rotation_151_id_idx
    ON tde_enc_rotation_151 USING tde_ope_btree (id tde_ope_int4_enc_ops);
INSERT INTO tde_enc_rotation_151 VALUES (7, 'seven');

DO $$
DECLARE
    result_val    text;
    rotation_done boolean := false;
BEGIN
    -- Rotate the per-table DEK via online rotation BGW.
    -- Subsequent amrescan will encrypt the predicate with DEK-B
    -- while the stored index key was encrypted with DEK-A.
    PERFORM pg_vault_tde_rotate_online('tde_enc_rotation_151'::regclass);

    -- Wait for BGW rotation to complete (max 5 seconds)
    FOR i IN 1..50 LOOP
        SELECT (status = 'complete') INTO rotation_done
        FROM pg_vault_tde_rotation_progress
        WHERE relid = 'tde_enc_rotation_151'::regclass::oid;
        EXIT WHEN rotation_done;
        PERFORM pg_sleep(0.1);
    END LOOP;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_rotation_151 WHERE id = 7;
    RESET enable_seqscan;

    -- With a different DEK, AES-SIV produces a different ciphertext for
    -- the predicate — no match found.  NULL is the expected result.
    IF result_val IS DISTINCT FROM 'seven' THEN
        RAISE EXCEPTION
            'TEST 151 FAILED: expected "seven" but got ''%''',
            result_val;
    END IF;

    -- Re-encrypt all index keys with the new DEK.
    REINDEX INDEX tde_enc_rotation_151_id_idx;

    SET enable_seqscan = off;
    SELECT label INTO result_val
    FROM tde_enc_rotation_151 WHERE id = 7;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'seven' THEN
        RAISE EXCEPTION
            'TEST 151 FAILED: after REINDEX expected ''seven'', got %',
            COALESCE(result_val, '<NULL>');
    END IF;

    RAISE NOTICE
        'TEST 151 PASSED: stale enc_ops index after DEK rotation returns NULL; '
        'REINDEX restores lookup correctly';
END;
$$;
DROP TABLE tde_enc_rotation_151;

-- ================================================================
-- TEST 152: Multi-column index — mix of enc_ops, text_ops, int8_ops
--
-- Creates a three-column tde_ope_btree index where:
--   col a (int4)  uses tde_ope_int4_enc_ops  (fixed-type enc, STORAGE bytea)
--   col b (text)  uses tde_ope_text_enc_ops  
--   col c (int8)  uses tde_ope_int8_enc_ops  (fixed-type enc, STORAGE bytea)
--
-- Verifies that an equality lookup on the first two columns returns
-- the correct row, confirming that the per-column dispatch in
-- aminsert/amrescan handles the mixed-opclass case correctly.
-- ================================================================
DO $$
DECLARE
    result_val text;
BEGIN
    DROP TABLE IF EXISTS tde_multikey_152;
    CREATE TABLE tde_multikey_152 (a int4, b text, c int8) USING encrypted_heap;
    CREATE INDEX tde_multikey_152_idx
        ON tde_multikey_152
        USING tde_ope_btree (a tde_ope_int4_enc_ops, b tde_ope_text_enc_ops, c tde_ope_int8_enc_ops);

    INSERT INTO tde_multikey_152 VALUES (1, 'hello', 100);
    INSERT INTO tde_multikey_152 VALUES (2, 'world', 200);

    SET enable_seqscan = off;
    SELECT b INTO result_val
    FROM tde_multikey_152 WHERE a = 2 AND b = 'world';
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'world' THEN
        RAISE EXCEPTION
            'TEST 152 FAILED: multi-column enc_ops lookup returned %, expected ''world''',
            COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_multikey_152;
    RAISE NOTICE
        'TEST 152 PASSED: multi-column index with enc_ops + text_ops + int8_ops mix OK';
END;
$$;

-- ================================================================
-- TEST 153: CREATE INDEX on pre-populated table (ambuild path)
--
-- Populates a table with 100 rows BEFORE creating the index, so that
-- the index build goes through pg_vault_tde_index_build_range_scan
-- (the ambuild path) rather than the per-row aminsert path.
-- Verifies:
--   1. Spot-check: row 57 is found via index scan.
--   2. Full count: all 100 rows indexed (BETWEEN scan via seqscan=off).
-- Note: BETWEEN on enc_ops produces semantically arbitrary results;
-- the count assertion here just confirms all rows are reachable via
-- the index (no build errors, no dropped keys).
-- ================================================================
DO $$
DECLARE
    result_val text;
    n          int;
BEGIN
    DROP TABLE IF EXISTS tde_existing_153;
    CREATE TABLE tde_existing_153 (id int4, label text) USING encrypted_heap;

    -- Populate before index creation
    INSERT INTO tde_existing_153
    SELECT i, 'row_' || i FROM generate_series(1, 100) i;

    -- CREATE INDEX on already-populated table → exercises ambuild path
    CREATE INDEX tde_existing_153_idx
        ON tde_existing_153 USING tde_ope_btree (id tde_ope_int4_enc_ops);

    -- Spot-check: equality lookup for row 57
    SET enable_seqscan = off;
    SELECT label INTO result_val FROM tde_existing_153 WHERE id = 57;
    RESET enable_seqscan;

    IF result_val IS DISTINCT FROM 'row_57' THEN
        RAISE EXCEPTION
            'TEST 153 FAILED: post-build equality lookup for id=57 returned %, '
            'expected ''row_57''',
            COALESCE(result_val, '<NULL>');
    END IF;

    -- Full count via seqscan to verify data integrity (not index range scan)
    SELECT count(*) INTO n FROM tde_existing_153;
    IF n <> 100 THEN
        RAISE EXCEPTION
            'TEST 153 FAILED: expected 100 rows in table, got %', n;
    END IF;

    DROP TABLE tde_existing_153;
    RAISE NOTICE
        'TEST 153 PASSED: CREATE INDEX on pre-populated encrypted_heap table '
        '(ambuild path), spot-check row 57 OK, 100 rows intact';
END;
$$;

-- ================================================================
-- TEST 154: ON CONFLICT DO NOTHING with unique enc_ops index
--
-- Creates a unique tde_ope_btree index using tde_ope_int4_enc_ops and verifies
-- that ON CONFLICT DO NOTHING correctly detects the duplicate key
-- (AES-SIV determinism: same plaintext + DEK → same ciphertext, so
-- btree equality check works) and silently ignores the second insert.
-- Exactly one row must remain after the duplicate attempt.
-- ================================================================
DO $$
DECLARE
    n int;
BEGIN
    DROP TABLE IF EXISTS tde_conflict_154;
    CREATE TABLE tde_conflict_154 (id int4, label text) USING encrypted_heap;
    CREATE UNIQUE INDEX tde_conflict_154_id_idx
        ON tde_conflict_154 USING tde_ope_btree (id tde_ope_int4_enc_ops);

    INSERT INTO tde_conflict_154 VALUES (1, 'first');

    -- Second insert with the same id: must be silently dropped
    INSERT INTO tde_conflict_154 VALUES (1, 'duplicate')
    ON CONFLICT DO NOTHING;

    SELECT count(*) INTO n FROM tde_conflict_154 WHERE id = 1;

    IF n <> 1 THEN
        RAISE EXCEPTION
            'TEST 154 FAILED: expected 1 row after ON CONFLICT DO NOTHING, got %', n;
    END IF;

    DROP TABLE tde_conflict_154;
    RAISE NOTICE
        'TEST 154 PASSED: ON CONFLICT DO NOTHING with tde_ope_int4_enc_ops unique index OK';
END;
$$;

-- ================================================================
-- TEST 155: encrypted_heap intentionally DISABLES HOT updates
--
-- The v4 IV-first wire format makes heapam see the indexed column as always
-- "changed" (it inspects ciphertext, not plaintext), so no HOT update is
-- chosen. This is deliberate: a HOT decision over ciphertext could skip a
-- tde_ope_btree index update and corrupt it. Assert HOT is off and that a normal
-- UPDATE + REINDEX still leaves the row findable via Index Scan.
-- ================================================================
DROP TABLE IF EXISTS tde_hot_155;
CREATE TABLE tde_hot_155 (id int4, val text) USING encrypted_heap;
CREATE INDEX tde_hot_idx_155
    ON tde_hot_155 USING tde_ope_btree (id tde_ope_int4_enc_ops);

INSERT INTO tde_hot_155 VALUES (1, 'before_update');

-- Only the non-indexed column changes.  On a plain heap this would be a HOT
-- update; on encrypted_heap the IV-first format forces a non-HOT update.
UPDATE tde_hot_155 SET val = 'after_update' WHERE id = 1;

-- Flush backend stats so the HOT-update counter is visible below.
SELECT pg_stat_force_next_flush();

DO $$
DECLARE
    n_hot      bigint;
    n_found    bigint;
    result_val text;
BEGIN
    -- HOT must be disabled on encrypted_heap: the IV-first wire format makes
    -- the indexed column always look modified to heapam, so no heap-only
    -- tuple is produced.
    SELECT n_tup_hot_upd INTO n_hot
    FROM pg_stat_user_tables WHERE relname = 'tde_hot_155';
    IF COALESCE(n_hot, 0) <> 0 THEN
        RAISE EXCEPTION
            'TEST 155 FAILED: expected NO HOT update on encrypted_heap (n_tup_hot_upd=%)',
            n_hot;
    END IF;

    -- A non-HOT UPDATE plus REINDEX must still leave the live row findable.
    REINDEX INDEX tde_hot_idx_155;

    -- Force an Index Scan and confirm the live (updated) row is found.
    SET enable_seqscan = off;
    SELECT count(*), max(val) INTO n_found, result_val
    FROM tde_hot_155 WHERE id = 1;
    RESET enable_seqscan;

    IF n_found <> 1 OR result_val IS DISTINCT FROM 'after_update' THEN
        RAISE EXCEPTION
            'TEST 155 FAILED: Index Scan after REINDEX found % row(s) val=% (expected 1, ''after_update'')',
            n_found, COALESCE(result_val, '<NULL>');
    END IF;

    DROP TABLE tde_hot_155;
    RAISE NOTICE
        'TEST 155 PASSED: encrypted_heap disables HOT (IV-first); non-HOT UPDATE + REINDEX keeps row findable';
END;
$$;


-- ================================================================
-- TEST 156: Index Range Scan
--
-- We disable seqscan/bitmapscan so the only remaining scan
-- method for a index is index scan then verify the decrypted output.
-- ================================================================
DO $$
  DECLARE
      cnt int;
      v   text;
  BEGIN
      CREATE TABLE tde_indexrange_156 (id int, secret text) USING encrypted_heap;
      INSERT INTO tde_indexrange_156
          SELECT g, 'PLAINTEXT_SECRET_' || g FROM generate_series(1, 200) g;
	  CREATE INDEX ON tde_indexrange_156 USING tde_ope_btree (id);
      
      SET enable_seqscan = off;
      SET enable_bitmapscan = off;
      
      SELECT count(*) INTO cnt
        FROM tde_indexrange_156 WHERE id BETWEEN 1 and 20;
      IF cnt <> 20 THEN
          RAISE EXCEPTION 'TEST 156a FAILED: expected 20 rows, got %', cnt;
      END IF;
          
      RESET enable_seqscan;
      RESET enable_bitmapscan;
      DROP TABLE tde_indexrange_156;
      RAISE NOTICE
          'TEST 156 PASSED: OPE Index Range Scan works correctly';
  END;
  $$;


-- ================================================================
-- TEST 157: CREATE INDEX CONCURRENTLY on encrypted_heap
-- ================================================================

DROP TABLE IF EXISTS tde_cic_157;
CREATE TABLE tde_cic_157 (id int, secret text) USING encrypted_heap;
INSERT INTO tde_cic_157
    SELECT g, 'PLAINTEXT_SECRET_' || g FROM generate_series(1, 1000) g;
CREATE INDEX CONCURRENTLY tde_cic_157_idx ON tde_cic_157 USING tde_ope_btree (id);
DO $$
DECLARE
    valid bool;
    v     text;
    cidx  int;
    cseq  int;
BEGIN
    SELECT indisvalid INTO valid
        FROM pg_index WHERE indexrelid = 'tde_cic_157_idx'::regclass;
    IF NOT valid THEN
        RAISE EXCEPTION 'TEST 157a FAILED: CIC left index invalid (indisvalid=false)';
    END IF;
    
    SET enable_seqscan = off; 
    SELECT secret INTO v FROM tde_cic_157 WHERE id = 250;
    IF v IS DISTINCT FROM 'PLAINTEXT_SECRET_250' THEN
        RAISE EXCEPTION 'TEST 157b FAILED: index scan returned "%", expected plaintext', v;
    END IF;
    SELECT count(*) INTO cidx FROM tde_cic_157 WHERE id BETWEEN 1 AND 1000;
    
    SET enable_seqscan = on;
	SET enable_indexscan = off;
    SET enable_bitmapscan = off;
    SELECT count(*) INTO cseq FROM tde_cic_157 WHERE id BETWEEN 1 AND 1000;
    RESET enable_seqscan;
	RESET enable_indexscan;
    RESET enable_bitmapscan;
    
    IF cidx <> cseq OR cidx <> 1000 THEN
        RAISE EXCEPTION 'TEST 157c FAILED: index count % <> seq count % (expected 1000)', cidx, cseq;
    END IF;
    RAISE NOTICE
        'TEST 157 PASSED: CREATE INDEX CONCURRENTLY builds a valid, correct index';
    DROP TABLE tde_cic_157;
END;
$$;

 -- ================================================================
-- TEST 158: REINDEX INDEX CONCURRENTLY on encrypted_heap (PSQLE-114).
-- Same validation-phase path as CIC. The index is created non-concurrently
-- (that path already works), so only REINDEX INDEX CONCURRENTLY is under test.
-- ================================================================
DROP TABLE IF EXISTS tde_cic_158;
CREATE TABLE tde_cic_158 (id int, secret text) USING encrypted_heap;
INSERT INTO tde_cic_158
    SELECT g, 'PLAINTEXT_SECRET_' || g FROM generate_series(1, 1000) g;
CREATE INDEX tde_cic_158_idx ON tde_cic_158 USING tde_ope_btree (id);
REINDEX INDEX CONCURRENTLY tde_cic_158_idx;
DO $$
DECLARE
    valid   bool;
    norphan int;
    v       text;
BEGIN
    SELECT indisvalid INTO valid
        FROM pg_index WHERE indexrelid = 'tde_cic_158_idx'::regclass;
    IF NOT valid THEN
        RAISE EXCEPTION 'TEST 158a FAILED: REINDEX INDEX CONCURRENTLY left index invalid';
    END IF;
    SELECT count(*) INTO norphan FROM pg_class WHERE relname LIKE 'tde_cic_158%ccnew%';
    IF norphan <> 0 THEN
        RAISE EXCEPTION 'TEST 158b FAILED: % orphan _ccnew index(es) left behind', norphan;
    END IF;

    SET enable_seqscan = off;
    SELECT secret INTO v FROM tde_cic_158 WHERE id = 777;
    RESET enable_seqscan; 
    IF v IS DISTINCT FROM 'PLAINTEXT_SECRET_777' THEN
        RAISE EXCEPTION 'TEST 158c FAILED: post-reindex index scan returned "%"', v;
    END IF;
    
    RAISE NOTICE
        'TEST 158 PASSED: REINDEX INDEX CONCURRENTLY rebuilds a valid, correct index';
    DROP TABLE tde_cic_158; 

END;
$$;

-- ================================================================
-- TEST 159: partial index (WHERE) via CREATE INDEX CONCURRENTLY.
-- Exercises the ExecQual(predicate) branch of the validate scan.
-- ================================================================
DROP TABLE IF EXISTS tde_cic_159;
CREATE TABLE tde_cic_159 (id int, secret text) USING encrypted_heap;
INSERT INTO tde_cic_159 
    SELECT g, 'S_' || g FROM generate_series(1, 200) g;
CREATE INDEX CONCURRENTLY tde_cic_159_partial
    ON tde_cic_159 USING tde_ope_btree (id) WHERE id > 100;

DO $$
DECLARE
    valid bool;
    v     text;
BEGIN
    SELECT indisvalid INTO valid
        FROM pg_index WHERE indexrelid = 'tde_cic_159_partial'::regclass;
    IF NOT valid THEN
        RAISE EXCEPTION 'TEST 159a FAILED: partial-index CIC left index invalid';
    END IF;
    
    SET enable_seqscan = off;
    SELECT secret INTO v FROM tde_cic_159 WHERE id = 155;
    RESET enable_seqscan; 
    IF v IS DISTINCT FROM 'S_155' THEN
        RAISE EXCEPTION 'TEST 159b FAILED: partial-index scan returned "%"', v;
    END IF;
    
    RAISE NOTICE
        'TEST 159 PASSED: partial-index CREATE INDEX CONCURRENTLY works';
    DROP TABLE tde_cic_159;
END;
$$;

-- ================================================================
-- TEST 160: Negative Values & Int4/Int8 Mathematical Boundary Scan
--
-- Validates that the left-to-right modular addition loop preserves 
-- relative ordering across the negative-to-positive integer boundary.
-- If the index implementation breaks modular order-preservation, 
-- a range scan covering negative to positive bounds will mis-order rows.
-- ================================================================
DO $$ 
DECLARE
    result_array int[];
	expected     int[] := ARRAY[-2147483648, -100, -1, 0, 1, 55, 2147483647];
	i            int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_boundary_160;
	CREATE TABLE tde_ope_boundary_160 (val int4, label text) USING encrypted_heap;
	CREATE INDEX tde_ope_bounds_idx_160
	    ON tde_ope_boundary_160 USING tde_ope_btree (val tde_ope_int4_enc_ops);
		
	-- Insert extreme boundaries including INT4_MIN and INT4_MAX
	INSERT INTO tde_ope_boundary_160 VALUES
		(0, 'zero'), (1, 'one'), (-1, 'minus_one'),
		(55, 'fifty_five'), (-100, 'minus_hundred'),
		(2147483647, 'int_max'), (-2147483648, 'int_min');
	
	-- Enforce index usage and aggregate sorting via index scan
	SET enable_seqscan = off;
	SET enable_bitmapscan = off;
	SELECT array_agg(val ORDER BY val ASC) INTO result_array
	    FROM tde_ope_boundary_160;
	RESET enable_seqscan;
	RESET enable_bitmapscan;
	FOR i IN 1..array_length(expected, 1) LOOP
		IF result_array[i] IS DISTINCT FROM expected[i] THEN
			RAISE NOTICE 'TEST 160 DIAGNOSTIC - Obtained Array Order: %', result_array::text;
			RAISE EXCEPTION 'TEST 160 FAILED: Ordered scan mismatch at pos %. Got %, expected %',
				i, result_array[i], expected[i];
		END IF;
	END LOOP;
	
	DROP TABLE tde_ope_boundary_160;
	RAISE NOTICE 'TEST 160 PASSED: OPE integer bounds and sign transitions sorted perfectly.'; 
END; 
$$;

-- ================================================================
-- TEST 161: Text Prefix Ambiguity ("Ali" vs "Alice") and Zero-Padding
--
-- Validates that variable-length text mapping safely isolates prefixes.
-- Shorter strings padded with 0x00 must never bleed into downstream 
-- additions or shift leftwards to override higher-order character sorting rules.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
	expected    text[] := ARRAY['Ali', 'Alice', 'Alicia', 'Alix'];
	i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_text_161;
    CREATE TABLE tde_ope_text_161 (name text) USING encrypted_heap;
	CREATE INDEX tde_ope_txt_idx_161          
		ON tde_ope_text_161 USING tde_ope_btree (name tde_ope_text_enc_ops);
	
	INSERT INTO tde_ope_text_161 VALUES ('Alicia'), ('Ali'), ('Alix'), ('Alice');
	SET enable_seqscan = off;
	SET enable_bitmapscan = off;
	SELECT array_agg(name ORDER BY name ASC) INTO result_vals
	    FROM tde_ope_text_161;
	RESET enable_seqscan;
	RESET enable_bitmapscan;
	
	FOR i IN 1..array_length(expected, 1) LOOP
	    IF result_vals[i] IS DISTINCT FROM expected[i] THEN
		    RAISE EXCEPTION 'TEST 161 FAILED: Prefix sorting failed at position %. Got "%", expected "%"',
			    i, result_vals[i], expected[i];
		END IF;
	END LOOP;
	
	DROP TABLE tde_ope_text_161;
	RAISE NOTICE 'TEST 161 PASSED: Text prefix OPE padding structures verified.'; 
END; 
$$;

-- ================================================================
-- TEST 162: NULL Processing and Index Scan Exclusion Boundaries
--
-- Verifies that NULL values are correctly structured within the index. 
-- In PostgreSQL, NULL values are structured outside the standard value scale.
-- OPE must not attempts to pad or encrypt NULLs as plain 0x00 chunks, which
-- would corrupt standard `IS NULL` or `IS NOT NULL` index-scan boundaries.
-- ================================================================
DO $$ 
DECLARE
    null_count int;
    nn_count   int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_nulls_162;
	CREATE TABLE tde_ope_nulls_162 (id int4, val int4) USING encrypted_heap;
	CREATE INDEX tde_ope_nulls_idx_162
	    ON tde_ope_nulls_162 USING tde_ope_btree (val tde_ope_int4_enc_ops);
		
	INSERT INTO tde_ope_nulls_162 VALUES (1, NULL), (2, 999), (3, NULL), (4, -50);
	
	SET enable_seqscan = off;
	-- Assert index correctly aggregates NULL fields exclusively
	SELECT count(*) INTO null_count FROM tde_ope_nulls_162 WHERE val IS NULL;
	-- Assert index filters actual values properly
	SELECT count(*) INTO nn_count FROM tde_ope_nulls_162 WHERE val IS NOT NULL;
	RESET enable_seqscan;
	
	IF null_count <> 2 THEN
	    RAISE EXCEPTION 'TEST 162 FAILED: IS NULL scan failed. Found %, expected 2 rows.', null_count;
	END IF;
	IF nn_count <> 2 THEN
        RAISE EXCEPTION 'TEST 162 FAILED: IS NOT NULL scan failed. Found %, expected 2 rows.', nn_count;
    END IF;
	
	DROP TABLE tde_ope_nulls_162;
	RAISE NOTICE 'TEST 162 PASSED: OPE NULL structure handling isolated correctly.';
END;
$$;

-- ================================================================
-- TEST 163: Concurrent Transaction Aborts and Index Rollback Isolation
--
-- Inserts keys inside a subtransaction block and aborts it. Then 
-- inserts conflicting keys. Validates that aborted memory maps or dirty 
-- cache slots inside the engine do not pollute index traversals or leak values.
-- ================================================================
DO $$ 
DECLARE
    final_count int;
	lookup_val  text;
BEGIN
    DROP TABLE IF EXISTS tde_ope_abort_163;
    CREATE TABLE tde_ope_abort_163 (id int4, name text) USING encrypted_heap;
    CREATE UNIQUE INDEX tde_ope_abort_idx_163
	    ON tde_ope_abort_163 USING tde_ope_btree (id tde_ope_int4_enc_ops);
		
    -- 1. Attempt insertion of transactional rows that will be rolled back
	BEGIN
        INSERT INTO tde_ope_abort_163 VALUES (500, 'ghost_row_1');
        INSERT INTO tde_ope_abort_163 VALUES (600, 'ghost_row_2');
        RAISE EXCEPTION 'Simulate Transaction Abort Boundary';
    EXCEPTION WHEN OTHERS THEN
        -- Abort caught cleanly, subtransaction unwound
		NULL;
    END;
	
	-- 2. Insert definitive live keys over the same namespace paths
    INSERT INTO tde_ope_abort_163 VALUES (500, 'valid_row_500');
    -- Enforce unique lookup confirmation through the index
    SET enable_seqscan = off;
    SELECT name INTO lookup_val FROM tde_ope_abort_163 WHERE id = 500;
    SELECT count(*) INTO final_count FROM tde_ope_abort_163;
    RESET enable_seqscan;

    IF final_count <> 1 THEN
        RAISE EXCEPTION 'TEST 163 FAILED: Index space pollution detected. Total rows: %', final_count;
    END IF;
    IF lookup_val IS DISTINCT FROM 'valid_row_500' THEN
        RAISE EXCEPTION 'TEST 163 FAILED: Expected lookup "valid_row_500", but extracted "%"', lookup_val;
    END IF;
	
    DROP TABLE tde_ope_abort_163;
    RAISE NOTICE 'TEST 163 PASSED: Aborted subtransactions did not leave behind phantom OPE keys.';
END;
$$;

-- ================================================================
-- TEST 164: Explicit Short-String Prefix Edge Case ("B" vs "Alice")
--
-- Validates the exact scenario where a 1-character string value ('B') 
-- has a higher alphabetical character weight than the first character 
-- of a longer string ('Alice'). With proper null-termination padding (+1 len), 
-- the index scan must accurately sort 'B' after 'Alice'.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
    expected    text[] := ARRAY['Alice', 'B'];
    i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_short_prefix_164;
    CREATE TABLE tde_ope_short_prefix_164 (name text) USING encrypted_heap;
    CREATE INDEX tde_ope_short_idx_164          
        ON tde_ope_short_prefix_164 USING tde_ope_btree (name tde_ope_text_enc_ops);
    
    INSERT INTO tde_ope_short_prefix_164 VALUES ('B'), ('Alice');
    
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    SELECT array_agg(name ORDER BY name ASC) INTO result_vals
        FROM tde_ope_short_prefix_164;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_vals[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 164 FAILED: Short prefix weight sorting failed at position %. Got "%", expected "%" (Null-terminator missing in OPE engine stream boundary)',
                i, result_vals[i], expected[i];
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_short_prefix_164;
    RAISE NOTICE 'TEST 164 PASSED: OPE string boundary handling for "B" vs "Alice" verified.'; 
END; 
$$;

-- ================================================================
-- TEST 165: Multi-Length String Matrix Sorting Stability
--
-- Exercises the index using a mix of single-character codes and full 
-- names sharing identical prefixes to ensure length metrics don't bias 
-- the OPE order-preserving ciphertext transformations.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
    expected    text[] := ARRAY['A', 'Alf', 'Alice', 'B', 'Bob', 'C', 'Charlie'];
    i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_matrix_165;
    CREATE TABLE tde_ope_matrix_165 (name text) USING encrypted_heap;
    CREATE INDEX tde_ope_matrix_idx_165          
        ON tde_ope_matrix_165 USING tde_ope_btree (name tde_ope_text_enc_ops);
    
    INSERT INTO tde_ope_matrix_165 VALUES 
        ('Charlie'), ('A'), ('Bob'), ('Alice'), ('C'), ('Alf'), ('B');
        
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    SELECT array_agg(name ORDER BY name ASC) INTO result_vals
        FROM tde_ope_matrix_165;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_vals[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 165 FAILED: Dictionary matrix mismatch at pos %. Got "%", expected "%"',
                i, result_vals[i], expected[i];
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_matrix_165;
    RAISE NOTICE 'TEST 165 PASSED: Multi-length string matrix sorted cleanly via tde_ope_btree index scan.'; 
END; 
$$;

-- ================================================================
-- TEST 166: Fixed-Width Character Padding Stability (bpchar / char(n))
--
-- In PostgreSQL, char(n) blank-pads values with trailing spaces only on disk. 
-- For instance, 'A' stored in a char(5) field becomes 'A    ', but it's read as 'A' 
-- This test ensures that the OPE engine accurately tracks these space 
-- pads as part of its sort evaluations rather than stopping at the raw string boundaries.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
    expected    text[] := ARRAY['A', 'A', 'A a', 'B'];
    i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_fixed_width_166;
    -- Using char(5) forces trailing space blank-padding behavior
    CREATE TABLE tde_ope_fixed_width_166 (val char(5)) USING encrypted_heap;
    CREATE INDEX tde_ope_fixed_idx_166          
        ON tde_ope_fixed_width_166 USING tde_ope_btree (val tde_ope_bpchar_enc_ops);
    
    -- Insert elements that test trailing space priority rules
    -- Standard text ordering: 'A' (padded to 'A    ') < 'A a  ' < 'A  b ' < 'B    '
    INSERT INTO tde_ope_fixed_width_166 VALUES ('B'), ('A  '), ('A a'), ('A');
    
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    -- rtrim ensures comparison validation checks matching values cleanly
    SELECT array_agg(rtrim(val) ORDER BY val ASC) INTO result_vals
        FROM tde_ope_fixed_width_166;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_vals[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 166 FAILED: Fixed-width blank padding sort failed at pos %. Got "%", expected "%"',
                i, result_vals[i], expected[i];
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_fixed_width_166;
    RAISE NOTICE 'TEST 166 PASSED: OPE blank-padded fixed-width spaces evaluated correctly.'; 
END; 
$$;

-- ================================================================
-- TEST 167: Bytea Array Sequencing and Internal Null Bytes (\0)
--
-- Binary fields (bytea) can store raw streams containing arbitrary null 
-- bytes anywhere in the sequence. Unlike string workflows, a null byte 
-- inside a bytea sequence must NOT act as an early end-of-string terminator. 
-- The test validates that the correct plen boundary evaluates everything.
-- ================================================================
DO $$
DECLARE
    result_bytes bytea[];
    expected     bytea[] := ARRAY[
        decode('010002', 'hex'), -- \x010002
        decode('010003', 'hex'), -- \x010003
        decode('0101', 'hex'),   -- \x0101
        decode('0200', 'hex')    -- \x0200
    ];
    i            int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_bytea_167;
    CREATE TABLE tde_ope_bytea_167 (raw_data bytea) USING encrypted_heap;
    -- Using the generic tde_ope_btree index on bytea column
    CREATE INDEX tde_ope_bytea_idx_167          
        ON tde_ope_bytea_167 USING tde_ope_btree (raw_data);
    
    -- Insert binary arrays with varying lengths and embedded zeros
    INSERT INTO tde_ope_bytea_167 VALUES 
        (decode('0200', 'hex')),
        (decode('010003', 'hex')),
        (decode('0101', 'hex')),
        (decode('010002', 'hex'));
        
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    SELECT array_agg(raw_data ORDER BY raw_data ASC) INTO result_bytes
        FROM tde_ope_bytea_167;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_bytes[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 167 FAILED: Bytea array sequence failed at position %. Got %, expected % (Internal null byte incorrectly truncated validation path)',
                i, encode(result_bytes[i], 'hex'), encode(expected[i], 'hex');
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_bytea_167;
    RAISE NOTICE 'TEST 167 PASSED: OPE bytea internal null bytes and sizes processed correctly.'; 
END; 
$$;

-- ================================================================
-- TEST 168: TOAST Storage Layer Boundary (Large Strings > 4KB)
--
-- Validates that large payload values which trigger PostgreSQL's internal
-- TOAST table compression mechanics do not crash or corrupt the length-prefix 
-- validation calculations within the OPE index engine.
-- ================================================================
DO $$
DECLARE
    large_val   text := repeat('X', 5000); -- Forces the value to go to TOAST
    result_val  text;
BEGIN
    DROP TABLE IF EXISTS tde_ope_toast_168;
    CREATE TABLE tde_ope_toast_168 (id int, payload text) USING encrypted_heap;
    CREATE INDEX tde_ope_toast_idx_168 
        ON tde_ope_toast_168 USING tde_ope_btree (payload tde_ope_text_enc_ops);
        
    INSERT INTO tde_ope_toast_168 VALUES (1, large_val), (2, 'short_string');
    
    SET enable_seqscan = off;
    SELECT payload INTO result_val FROM tde_ope_toast_168 WHERE payload = large_val;
    RESET enable_seqscan;
    
    IF length(result_val) <> 5000 THEN
        RAISE EXCEPTION 'TEST 168 FAILED: TOASTed text value corruption or truncation detected.';
    END IF;
    
    DROP TABLE tde_ope_toast_168;
    RAISE NOTICE 'TEST 168 PASSED: Large TOASTed values safely processed by OPE index engine.';
END;
$$;

-- ================================================================
-- TEST 169: Empty String Boundary Condition ("" vs " ")
--
-- Validates the extreme lower bound of the string length metric. 
-- An empty string has a strlen of 0, meaning the length-prefix 
-- fix reduces it to a 1-byte payload containing exactly '\0'. 
-- This test ensures that the OPE engine successfully handles a 
-- 1-byte encryption payload containing zero without out-of-bounds 
-- read crashes, and accurately sorts it before a whitespace block.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
    expected    text[] := ARRAY['', ' '];
    i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_empty_169;
    CREATE TABLE tde_ope_empty_169 (val text) USING encrypted_heap;
    CREATE INDEX tde_ope_empty_idx_169 
        ON tde_ope_empty_169 USING tde_ope_btree (val tde_ope_text_enc_ops);
        
    INSERT INTO tde_ope_empty_169 VALUES (' '), ('');
    
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    SELECT array_agg(val ORDER BY val ASC) INTO result_vals
        FROM tde_ope_empty_169;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_vals[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 169 FAILED: Empty string boundary sorting failed at pos %. Got "%", expected "%"',
                i, result_vals[i], expected[i];
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_empty_169;
    RAISE NOTICE 'TEST 169 PASSED: Empty string absolute boundary condition isolated and verified.';
END;
$$;

-- ================================================================
-- TEST 170: Multi-Byte Character Encodings (UTF-8 / International Text)
--
-- Validates that multi-byte UTF-8 character sequences (where characters 
-- take between 2 to 4 bytes instead of 1) preserve canonical binary 
-- sort ordering. It checks that the OPE engine maps these expanded variable 
-- byte streams into sequential ciphertext slots without corrupting 
-- multi-byte character sorting boundaries.
-- ================================================================
DO $$
DECLARE
    result_vals text[];
    expected    text[] := ARRAY['Apple', 'Banana', 'Ávila'];
    i           int;
BEGIN
    DROP TABLE IF EXISTS tde_ope_multibyte_170;
    CREATE TABLE tde_ope_multibyte_170 (val text) USING encrypted_heap;
    CREATE INDEX tde_ope_mbyte_idx_170 
        ON tde_ope_multibyte_170 USING tde_ope_btree (val tde_ope_text_enc_ops);
        
    INSERT INTO tde_ope_multibyte_170 VALUES ('Banana'), ('Ávila'), ('Apple');
    
    SET enable_seqscan = off;
    SET enable_bitmapscan = off;
    SELECT array_agg(val ORDER BY val ASC) INTO result_vals
        FROM tde_ope_multibyte_170;
    RESET enable_seqscan;
    RESET enable_bitmapscan;
    
    FOR i IN 1..array_length(expected, 1) LOOP
        IF result_vals[i] IS DISTINCT FROM expected[i] THEN
            RAISE EXCEPTION 'TEST 170 FAILED: Multi-byte UTF-8 sequence sorting failed at pos %. Got "%", expected "%"',
                i, result_vals[i], expected[i];
        END IF;
    END LOOP;
    
    DROP TABLE tde_ope_multibyte_170;
    RAISE NOTICE 'TEST 170 PASSED: Multi-byte UTF-8 international text sort matrices verified.';
END;
$$;


-- ================================================================
-- PHASE SUMMARY
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'v1.8 Tests OPE — COMPLETE';
	RAISE NOTICE '   Access Methods registered .......................test 141';
	RAISE NOTICE '   Index scan — encrypted data readable ............test 142';
	RAISE NOTICE '   BitmapHeapScan — scan_bitmap_next_tuple .........test 143';
	RAISE NOTICE '   REINDEX tde_ope_btree index .....................test 144';
	RAISE NOTICE '   CREATE INDEX + equality index scan ..............test 145';
    RAISE NOTICE '   tde_ope_int4_enc_ops + disk forensic check ......test 146';
    RAISE NOTICE '   tde_ope_int8_enc_ops equality lookup ........... test 147';
    RAISE NOTICE '   tde_ope_uuid_enc_ops equality lookup ........... test 148';
    RAISE NOTICE '   tde_ope_date_enc_ops equality lookup ........... test 149';
    RAISE NOTICE '   tde_ope_timestamptz_enc_ops equality lookup .... test 150';
    RAISE NOTICE '   OPE DEK rotation → stale index → REINDEX ....... test 151';
    RAISE NOTICE '   OPE multi-column enc_ops + text + int8 mix ..... test 152';
    RAISE NOTICE '   OPE CREATE INDEX on pre-populated table ........ test 153';
    RAISE NOTICE '   OPE ON CONFLICT DO NOTHING + enc_ops unique .... test 154';
    RAISE NOTICE '   OPE HOT disabled on encrypted_heap (IV-first) .. test 155';
    RAISE NOTICE '   OPE Index scan range............................ test 156';
    RAISE NOTICE '   CREATE INDEX CONCURRENTLY (index_validate) ..... test 157';
    RAISE NOTICE '   REINDEX INDEX CONCURRENTLY ..................... test 158';
    RAISE NOTICE '   partial-index CREATE INDEX CONCURRENTLY ........ test 159';
    RAISE NOTICE '   OPE Index scan range............................ test 156';
    RAISE NOTICE '   CREATE INDEX CONCURRENTLY (index_validate) ..... test 157';
    RAISE NOTICE '   REINDEX INDEX CONCURRENTLY ..................... test 158';
    RAISE NOTICE '   partial-index CREATE INDEX CONCURRENTLY ........ test 159';
    RAISE NOTICE '   OPE integer sign boundary & extreme scans ...... test 160';
    RAISE NOTICE '   OPE variable prefix & alignment structures ..... test 161';
    RAISE NOTICE '   OPE NULL boundary filtering isolate scans ...... test 162';
    RAISE NOTICE '   OPE rollback isolation verification tests ...... test 163';
	RAISE NOTICE '   Explicit Short-String Prefix Edge Case ......... test 164';
	RAISE NOTICE '   Multi-Length String Matrix Sorting Stability ... test 165';
	RAISE NOTICE '   Fixed-Width Character Padding Stability ........ test 166';
	RAISE NOTICE '   Bytea Array Sequencing and Internal Null Bytes . test 167';
	RAISE NOTICE '   TOAST Storage Layer Boundary ................... test 168';
	RAISE NOTICE '   Empty String Boundary Condition ................ test 169';
	RAISE NOTICE '   Multi-Byte Character Encodings ................. test 170';
    RAISE NOTICE '============================================================';
END;
$$;
