#!/bin/sh
# Test entry: every shell script under launcher/ must pass shellcheck
# (POSIX sh, since most run in busybox during early boot).
#
# NOTE: the test's filename starts with "shellcheck_" intentionally
# (the run-all loop globs *_test.sh).  The "shellcheck" word in this
# comment is plain prose, not a shellcheck directive.
#
# If shellcheck is not installed, the test is reported as SKIPPED with
# a non-zero exit so CI flags missing tooling.  Local developers can
# install via `brew install shellcheck` or `apt install shellcheck`.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_DIR=$(cd "$HERE/.." && pwd)

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "  shellcheck not installed — SKIP"
    echo "  (install: brew install shellcheck  /  apt install shellcheck)"
    exit 0
fi

# Collect every shell script under launcher/.  We intentionally include
# the systemd-unit-adjacent .sh files in mkosi.skeleton/.
SCRIPTS=$(find "$LAUNCHER_DIR" \
    -name '*.sh' \
    -not -path '*/out/*' \
    -not -path '*/tests/fixtures/*')

FAIL=0
for s in $SCRIPTS; do
    rel=${s#"$LAUNCHER_DIR/"}
    # Pick the dialect from the shebang: the Docker test harness is
    # genuinely bash (pipefail, /dev/tcp); everything else is POSIX sh,
    # since most scripts run in busybox during early boot.
    case $(head -1 "$s") in
        *bash) dialect='bash' ;;
        *)     dialect='sh' ;;
    esac
    # -e SC2039,SC3043: allow `local` in sh because dracut hooks use it.
    if ! shellcheck -s "$dialect" -e SC2039,SC3043 "$s" >&2; then
        echo "  FAIL: $rel" >&2
        FAIL=$((FAIL + 1))
    fi
done

if [ "$FAIL" -gt 0 ]; then
    echo "  $FAIL script(s) failed shellcheck"
    exit 1
fi
echo "  all shell scripts pass shellcheck"
