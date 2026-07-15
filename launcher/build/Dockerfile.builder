# Dockerfile.builder — pinned builder image for reproducible TD image
# construction.  Auditors must use this exact image (by digest) to
# reproduce the published artifacts.
#
# We pin to a specific Debian digest.  Floating tags (e.g. "debian:trixie")
# are forbidden because the underlying image changes silently.  build/build.sh
# refuses to run while this file carries PLACEHOLDER_REPLACE_AT_RELEASE_CUT
# (override for dev builds with ALLOW_UNPINNED_BUILDER=1).  At a release cut,
# re-resolve the digest of the chosen `debian:trixie-<date>` tag and update it
# here together with APT_SNAPSHOT_URL.  See build/README.md for the protocol.
FROM debian@sha256:fe7312b5f05bf5f43fad76bcd8945642e4e47a68aefd1b73f447615899d0fac1 AS builder

# Avoid interactive package prompts; keep apt deterministic.
ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C
ENV TZ=UTC

# Development builds use the base image's default trixie sources (pinned by
# the FROM digest above).  At a release cut, repoint apt at a matching
# snapshot.debian.org suite for full version pinning — see build/README.md.

# Build tools.  This set provides mkosi 25.3 (systemd-repart disk format),
# the UKI toolchain, and the filesystem/verity utilities mkosi shells out to.
# veritysetup ships inside cryptsetup-bin; sha256sum inside coreutils — neither
# is a standalone package.  Versions are not pinned here (they vary by
# snapshot); build/build.sh validates resolved versions against the manifest.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      mkosi \
      systemd \
      systemd-container \
      systemd-boot \
      systemd-ukify \
      systemd-resolved \
      dosfstools \
      mtools \
      e2fsprogs \
      btrfs-progs \
      squashfs-tools \
      cryptsetup-bin \
      dracut \
      kmod \
      zstd \
      reprepro \
      apt-utils \
      jq \
      xxd \
      python3 \
      python3-pip \
      ca-certificates \
      git \
 && rm -rf /var/lib/apt/lists/*

# Install the keccak backend for verify-* scripts.  Pinned by version.
RUN pip install --no-cache-dir --break-system-packages \
      eth-utils==5.1.0 \
      "eth-hash[pycryptodome]==0.7.0"

# Deterministic ext4 hash_seed.  systemd-repart's --seed derives every
# GPT/partition/filesystem UUID, but it does NOT pass the ext4 htree
# hash_seed to mke2fs, so mke2fs randomizes it per build and the resulting
# images diverge (and cascade through dm-verity roothash -> partition UUIDs
# -> GPT).  Wrap mke2fs to append a fixed hash_seed LAST: repart appends its
# own -E options, and a later -E without hash_seed re-randomizes it, so ours
# must come after the caller's args to win.  mkfs.ext{2,3,4} symlink to
# mke2fs, so this covers every ext call repart makes.
RUN mv /usr/sbin/mke2fs /usr/sbin/mke2fs.real \
 && { echo '#!/bin/sh'; \
      echo 'exec /usr/sbin/mke2fs.real "$@" -E hash_seed=fa11feed-1111-4222-8333-444455556666'; \
    } > /usr/sbin/mke2fs \
 && chmod +x /usr/sbin/mke2fs

WORKDIR /work
