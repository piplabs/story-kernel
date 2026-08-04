#!/bin/bash
# build-kernel.sh — reproducible, KEYLESS custom TDX kernel for the launcher image.
#
# Produces linux-image-6.18.35-storytdx_*_amd64.deb from vanilla Linux 6.18.35
# plus the pinned config in this directory. The build is:
#   - keyless: CONFIG_MODULE_SIG=n (no module-signing X.509 cert is embedded), so
#     anyone can rebuild byte-identically WITHOUT a private signing key. Module
#     signing is unenforced here anyway (dm-verity + measured boot + the on-chain
#     code/platform commitment are the integrity controls), so dropping it costs
#     no security and removes the only non-deterministic input.
#   - deterministic: fixed KBUILD_BUILD_* + SOURCE_DATE_EPOCH + pinned .version.
#
# The resulting .deb is staged into ../mkosi/mkosi.packages/ and installed by
# mkosi (which references it by package name `linux-image-6.18.35-storytdx`).
#
# Usage: ./build-kernel.sh [output.deb]   (run inside the pinned builder; needs
#        build-essential, bc, bison, flex, libelf-dev, libssl-dev, dpkg-dev)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VER=6.18.35
OUT="${1:-$HERE/linux-image-${VER}-storytdx.deb}"
WORK="${KERNEL_WORKDIR:-/tmp/storytdx-kbuild}"
SRC="$WORK/linux-$VER"

# Pin the upstream tarball hash so a poisoned mirror or MITM cannot substitute
# a different "reproducible" kernel (which would still build deterministically,
# just from attacker-chosen source). Value taken from the GPG-signed
# https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc and verified
# against the "Kernel.org checksum autosigner <autosigner@kernel.org>" key
# (fpr B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1) for linux-6.18.35.tar.xz.
KERNEL_TARBALL_SHA256="${KERNEL_TARBALL_SHA256:-f78602932219125e211c5f5bfd84edcfd4ec5ce88fc944f8248413f665bef236}"

mkdir -p "$WORK"
# Always start from a clean source tree so the pinned-hash verification below
# can never be skipped by a stale or tampered workdir: a reused $SRC (e.g. on a
# long-lived builder) would otherwise bypass the sha256 check entirely.
rm -rf "$SRC"
if [ ! -d "$SRC" ]; then
    echo "build-kernel: fetching linux-$VER"
    TARBALL="$WORK/linux-$VER.tar.xz"
    curl -sSL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$VER.tar.xz" -o "$TARBALL"
    if [ "$KERNEL_TARBALL_SHA256" = "PLACEHOLDER_REPLACE_AT_RELEASE_CUT" ]; then
        if [ "${ALLOW_UNPINNED_KERNEL:-0}" = "1" ]; then
            echo "build-kernel: WARNING — kernel tarball hash is unpinned; source is not verified." >&2
        else
            echo "build-kernel: ERROR — KERNEL_TARBALL_SHA256 is unpinned." >&2
            echo "build-kernel:   Pin it to the GPG-verified upstream sha256, or set" >&2
            echo "build-kernel:   ALLOW_UNPINNED_KERNEL=1 for a non-verified dev build." >&2
            exit 1
        fi
    else
        echo "${KERNEL_TARBALL_SHA256}  ${TARBALL}" | sha256sum -c - || {
            echo "build-kernel: ERROR — kernel tarball sha256 mismatch (poisoned mirror?)." >&2
            exit 1
        }
    fi
    tar -C "$WORK" -xf "$TARBALL"
fi
cd "$SRC"

# Start from the pinned config, then enforce the keyless/no-lockdown invariants
# explicitly (lockdown's `select MODULE_SIG if MODULES` would otherwise pull
# module signing back in) and resolve any NEW symbols to defaults non-interactively.
cp -f "$HERE/config-${VER}-storytdx" .config
scripts/config --set-str LOCALVERSION "-storytdx"
scripts/config -d SECURITY_LOCKDOWN_LSM -d SECURITY_LOCKDOWN_LSM_EARLY \
               -d MODULE_SIG -d MODULE_SIG_ALL -d MODULE_SIG_FORCE
make olddefconfig </dev/null
if grep -q "^CONFIG_MODULE_SIG=y" .config; then
    echo "build-kernel: ABORT — MODULE_SIG re-enabled (a lockdown/IMA symbol still selects it)" >&2
    exit 1
fi

# Deterministic build identity.
export KBUILD_BUILD_TIMESTAMP="Tue Nov 14 22:13:20 UTC 2023" \
       KBUILD_BUILD_USER="story" KBUILD_BUILD_HOST="storytdx" \
       KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=1700000000
rm -rf debian; make clean >/dev/null 2>&1; rm -f .version
make -j"$(nproc)" KBUILD_BUILD_VERSION=1 </dev/null
make bindeb-pkg -j"$(nproc)" KBUILD_BUILD_VERSION=1 </dev/null

# Pick the non-debug linux-image .deb via a glob (no ls|grep).
DEB=""
for f in "$WORK"/linux-image-*_amd64.deb; do
    case "$f" in *dbg*) continue ;; esac
    [ -f "$f" ] && DEB="$f"
done
if [ -z "$DEB" ]; then
    echo "build-kernel: ABORT — no linux-image .deb produced" >&2
    exit 1
fi

# ASSERT the PRODUCED .deb is genuinely keyless + correctly named (do not trust
# the pre-build .config; the deb-pkg flow is what ends up in the image).
tmp=$(mktemp -d); dpkg-deb -x "$DEB" "$tmp"
set -- "$tmp"/boot/config-*
dc=$1
grep -q "^CONFIG_MODULE_SIG=y" "$dc" && { echo "build-kernel: ASSERT FAIL — built kernel has MODULE_SIG=y" >&2; exit 2; }
[ "$(dpkg-deb -f "$DEB" Package)" = "linux-image-${VER}-storytdx" ] || { echo "build-kernel: ASSERT FAIL — package name mismatch" >&2; exit 3; }
rm -rf "$tmp"

cp -f "$DEB" "$OUT"
echo "build-kernel: OK (keyless, MODULE_SIG=n) -> $OUT"
sha256sum "$OUT"
