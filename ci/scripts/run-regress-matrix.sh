#!/usr/bin/env bash
# ci/scripts/run-regress-matrix.sh — Run the SQL regression suite on the
# supported PostgreSQL majors OTHER than the default one.
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
# 18 is deliberately absent from the default list: the ordinary `regress` stage
# already runs it, and repeating it here would just double that cost.
#
# A major whose base image does not exist yet is SKIPPED, not failed -- PG 19 is
# still in development at the time of writing, and this stage starts covering it
# by itself the day docker.io/library/postgres:19 is published.  Override with:
#
#     PG_MAJORS="17 19" make ci-regress-matrix
#
# Exit code: 0 if every available major passed, 14 otherwise.
#
# Copyright (c) 2026 Miriade S.r.l. — PostgreSQL License (BSD)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# lib.sh sets -e; this script aggregates results and must not die on the first
# failing major.
set +e

PG_MAJORS="${PG_MAJORS:-17 19}"

log_stage "REGRESSION MATRIX (PG $PG_MAJORS)"

RC=0
declare -a SUMMARY=()

for major in $PG_MAJORS; do
    if ! $RT manifest inspect "docker.io/library/postgres:${major}" >/dev/null 2>&1; then
        log_warn "PG ${major}: base image not published yet — SKIPPED"
        SUMMARY+=("  PG ${major}  SKIPPED (no postgres:${major} image)")
        continue
    fi

    log_info "── PG ${major} ───────────────────────────────────────────────"
    START=$(timer_start)

    # A per-major image tag, so the majors do not overwrite each other's build
    # and the default pg-tde-test:latest used by every other stage is left
    # alone.
    if PG_VERSION="$major" \
       PG_TEST_IMAGE="pg-tde-test-pg${major}" \
       bash "$SCRIPT_DIR/run-regress.sh"; then
        SUMMARY+=("  PG ${major}  PASSED ($(timer_fmt "$(timer_elapsed "$START")"))")
        log_ok "PG ${major}: regression suite passed"
    else
        RC=14
        SUMMARY+=("  PG ${major}  FAILED ($(timer_fmt "$(timer_elapsed "$START")"))")
        log_error "PG ${major}: regression suite FAILED"
    fi
done

echo ""
log_info "── matrix summary ───────────────────────────────────────────"
printf '%s\n' "${SUMMARY[@]}"
echo ""

if [ "$RC" -ne 0 ]; then
    log_error "REGRESSION MATRIX: at least one major failed"
    exit "$RC"
fi

log_ok "REGRESSION MATRIX: every available major passed"
exit 0
