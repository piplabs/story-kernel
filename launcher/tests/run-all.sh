#!/bin/sh
# launcher/tests/run-all.sh — entry point for the local test tier.
#
# Runs every *_test.sh in this directory (alphabetical), accumulates
# pass/fail counts, exits non-zero if any fail.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)

PASS=0
FAIL=0
FAILED_NAMES=""

for t in "$HERE"/*_test.sh; do
    name=${t##*/}
    printf '== %s ==\n' "$name"
    if sh "$t"; then
        PASS=$((PASS + 1))
        printf '   PASS\n\n'
    else
        FAIL=$((FAIL + 1))
        FAILED_NAMES="$FAILED_NAMES $name"
        printf '   FAIL\n\n'
    fi
done

printf '== Summary ==\n'
printf '  Passed: %d\n' "$PASS"
printf '  Failed: %d\n' "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '  Failed tests:%s\n' "$FAILED_NAMES"
    exit 1
fi
exit 0
