#!/bin/sh
# launcher/boot/diff-cmdline.sh — check that boot/kernel-cmdline and
# mkosi/mkosi.conf KernelCommandLine agree on every flag.
#
# Drift between these two is silent: the build still works, but the
# RTMR1 of the produced image will not match the published
# platform_commitment because mkosi.conf is the one that actually
# affects the boot.
#
# Run as part of build/build.sh and as a CI lint.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_DIR=$(cd "$HERE/.." && pwd)

CMDLINE_FILE="$HERE/kernel-cmdline"
MKOSI_CONF="$LAUNCHER_DIR/mkosi/mkosi.conf"

if [ ! -r "$CMDLINE_FILE" ]; then
    echo "diff-cmdline: missing $CMDLINE_FILE" >&2
    exit 1
fi
if [ ! -r "$MKOSI_CONF" ]; then
    echo "diff-cmdline: missing $MKOSI_CONF" >&2
    exit 1
fi

# Extract flags from kernel-cmdline: strip comments and blank lines.
EXPECTED=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$CMDLINE_FILE" \
           | awk '!/^[[:space:]]*$/ { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print }')

# Extract flags from mkosi.conf KernelCommandLine= block.  mkosi
# accepts either single-line (`Foo=a b c`) or multiline (one flag
# per continuation line, each starting with whitespace).
#
# Algorithm:
#   1. On the `KernelCommandLine=` line itself: strip the `Foo=` prefix.
#      Print whatever remains (single-line case); mark in_block=1.
#   2. While in_block, keep printing whitespace-prefixed lines.
#   3. On the first non-whitespace line, end the block.
ACTUAL=$(awk '
    /^KernelCommandLine[[:space:]]*=/ {
        sub(/^[^=]*=/, "")
        if ($0 != "") print
        in_block=1
        next
    }
    in_block && /^[[:space:]]/ { print; next }
    in_block { in_block=0 }
' "$MKOSI_CONF" \
    | sed -e 's/#.*//' \
    | awk '{ for (i=1;i<=NF;i++) print $i }')

# Sort each side and diff.  Order is a separate concern (see
# kernel-cmdline header note); for now we only check membership.
EXPECTED_SORTED=$(printf '%s\n' "$EXPECTED" | sort -u)
ACTUAL_SORTED=$(printf '%s\n' "$ACTUAL"   | sort -u)

# Tolerate flags that the cmdline file leaves for the build pipeline
# to fill in at verity time (root=, roothash=, systemd.verity*).
EXPECTED_FILTERED=$(printf '%s\n' "$EXPECTED_SORTED" | grep -vE '^(root=|roothash=|systemd\.verity)' || true)
ACTUAL_FILTERED=$(printf '%s\n'   "$ACTUAL_SORTED"   | grep -vE '^(root=|roothash=|systemd\.verity)' || true)

if [ "$EXPECTED_FILTERED" = "$ACTUAL_FILTERED" ]; then
    echo "diff-cmdline: PASS — boot/kernel-cmdline and mkosi.conf agree"
    exit 0
fi

echo "diff-cmdline: FAIL — boot/kernel-cmdline and mkosi.conf disagree" >&2
echo "--- expected (boot/kernel-cmdline)" >&2
printf '%s\n' "$EXPECTED_FILTERED" >&2
echo "+++ actual (mkosi.conf)" >&2
printf '%s\n' "$ACTUAL_FILTERED" >&2
exit 1
