#!/usr/bin/env bash
# ci/scripts/run-matrix.sh — Run the SQL regression suite AND the TAP suite on
# the supported PostgreSQL majors OTHER than the default one.
#
# The packaging matrix (packaging/build-matrix.json) already covers PG 17..19,
# but only for *installing* the package.  Every test stage runs against a single
# major -- 18, the image default -- so a change that compiles everywhere and
# misbehaves on 17 ships green.  That gap is not hypothetical for this codebase:
# pg_vault_tde_ambuild carries a PG17-specific impersonation
# (tuplesort_begin_index_btree asserted there), the TAM notes a PG17 read-stream
# requirement in heapgettup, and the TAM/IAM impersonate core structures whose
# layout and identity checks move between majors.
#
# The TAP suite is in here for a reason, learned the hard way: tap/20_ondisk_fuzz.t
# passed locally on PG 18 and broke the GitHub pipeline on PG 17, because
# initdb's --no-data-checksums flag only exists from PG 18.  TAP tests lean on
# the PostgreSQL::Test framework and on initdb/pg_ctl option spellings, all of
# which move between majors far more than SQL does -- so they are exactly the
# stage that most needs cross-version coverage, and the one that had none.
#
# 18 is deliberately absent from the default list: the ordinary `regress` and
# `tap` stages already run it, and repeating it here would just double that
# cost.
#
# A major whose base image does not exist yet is SKIPPED, not failed -- PG 19 is
# still in development at the time of writing, and this stage starts covering it
# by itself the day docker.io/library/postgres:19 is published.  Override with:
#
#     PG_MAJORS="17 19" make ci-matrix
#
# Exit code: 0 if every suite passed on every available major, 14 otherwise.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# lib.sh sets -e; this script aggregates results and must not die on the first
# failing major.
set +e

PG_MAJORS="${PG_MAJORS:-17 19}"

log_stage "CROSS-VERSION MATRIX (PG $PG_MAJORS — regress + tap)"

RC=0
declare -a SUMMARY=()

for major in $PG_MAJORS; do
    if ! $RT manifest inspect "docker.io/library/postgres:${major}" >/dev/null 2>&1; then
        log_warn "PG ${major}: base image not published yet — SKIPPED"
        SUMMARY+=("  PG ${major}  SKIPPED (no postgres:${major} image)")
        continue
    fi

    log_info "── PG ${major} ───────────────────────────────────────────────"

    # A per-major image tag, so the majors do not overwrite each other's build
    # and the default pg-tde-test:latest used by every other stage is left
    # alone.
    for suite in regress tap; do
        START=$(timer_start)
        if PG_VERSION="$major" \
           PG_TEST_IMAGE="pg-tde-test-pg${major}" \
           bash "$SCRIPT_DIR/run-${suite}.sh"; then
            SUMMARY+=("  PG ${major}  ${suite}   PASSED ($(timer_fmt "$(timer_elapsed "$START")"))")
            log_ok "PG ${major}: ${suite} suite passed"
        else
            RC=14
            SUMMARY+=("  PG ${major}  ${suite}   FAILED ($(timer_fmt "$(timer_elapsed "$START")"))")
            log_error "PG ${major}: ${suite} suite FAILED"
        fi
    done
done

echo ""
log_info "── matrix summary ───────────────────────────────────────────"
printf '%s\n' "${SUMMARY[@]}"
echo ""

if [ "$RC" -ne 0 ]; then
    log_error "MATRIX: at least one suite failed"
    exit "$RC"
fi

log_ok "MATRIX: every suite passed on every available major"
exit 0
