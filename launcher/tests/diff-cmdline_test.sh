#!/bin/sh
# diff-cmdline_test.sh — synthetic tests for boot/diff-cmdline.sh.
#
# Builds throwaway kernel-cmdline + mkosi.conf pairs, then asserts that
# diff-cmdline.sh accepts agreeing pairs and rejects drifting pairs.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_DIR=$(cd "$HERE/.." && pwd)
REAL_SCRIPT="$LAUNCHER_DIR/boot/diff-cmdline.sh"

WORKDIR=$(mktemp -d -t diff-cmdline-test-XXXXXX)
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# Stage a fake launcher tree.  We COPY the script (not symlink) so its
# self-location lookup (`cd $(dirname $0)`) lands inside our workdir
# rather than back at the real script's directory — symlinks get
# resolved by cd/pwd on most shells.
mkdir -p "$WORKDIR/launcher/boot" "$WORKDIR/launcher/mkosi"
cp "$REAL_SCRIPT" "$WORKDIR/launcher/boot/diff-cmdline.sh"
chmod +x "$WORKDIR/launcher/boot/diff-cmdline.sh"
SCRIPT="$WORKDIR/launcher/boot/diff-cmdline.sh"

run_case() {
    case_name=$1
    expected=$2   # "pass" or "fail"
    cmdline=$3
    mkosi=$4

    printf '%s' "$cmdline" > "$WORKDIR/launcher/boot/kernel-cmdline"
    printf '%s' "$mkosi"   > "$WORKDIR/launcher/mkosi/mkosi.conf"

    if sh "$SCRIPT" >/dev/null 2>&1; then
        actual=pass
    else
        actual=fail
    fi
    if [ "$actual" != "$expected" ]; then
        echo "  CASE '$case_name' FAILED: expected $expected, got $actual"
        return 1
    fi
    echo "  case '$case_name' OK ($actual)"
}

# Case 1: identical sets PASS.
run_case "identical sets" pass \
"quiet
selinux=0
" \
"KernelCommandLine=
        quiet
        selinux=0
"

# Case 2: missing flag in mkosi FAIL.
run_case "missing in mkosi" fail \
"quiet
selinux=0
audit=0
" \
"KernelCommandLine=
        quiet
        selinux=0
"

# Case 3: extra flag in mkosi FAIL.
run_case "extra in mkosi" fail \
"quiet
" \
"KernelCommandLine=
        quiet
        rogue=flag
"

# Case 4: verity-related placeholders in kernel-cmdline tolerated.
run_case "verity placeholders tolerated" pass \
"quiet
# Filled in by build pipeline:
root=PARTUUID=...
roothash=...
systemd.verity_root_data=...
" \
"KernelCommandLine=
        quiet
"

# Case 5: comments and blank lines ignored.
run_case "comments and blanks ignored" pass \
"# Top comment
quiet

# Mid comment
selinux=0
" \
"KernelCommandLine=
        quiet
        selinux=0  # trailing
"
