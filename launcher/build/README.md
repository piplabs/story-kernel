# build/

Reproducible build pipeline. Auditors must be able to rebuild the image
from source and obtain byte-identical artifacts.

## Contents

| File | Purpose |
|---|---|
| `Dockerfile.builder` | Pinned builder image (Debian + mkosi + tools) |
| `build.sh` | Top-level entry — builds binary, runs mkosi, dm-verity, manifest |
| `verify-reproducible.sh` | Auditor lint — builds twice, diffs every artifact |
| `README.md` | This file |

## Determinism

- Builder image pinned to a specific Debian digest (set at release cut).
- `SOURCE_DATE_EPOCH` derived from the most recent commit touching
  `launcher/` or `enclave/tdx/`.
- Go build uses `-trimpath`, `-buildid=`, stripped (`-s -w`).
- mkosi consumes the pinned snapshot.debian.org URL when invoked with
  `APT_SNAPSHOT_URL=https://snapshot.debian.org/...`.

## Output artifacts (under `launcher/out/`)

| File | Description |
|---|---|
| `story-kernel` | The Go binary (sha256 in manifest) |
| `*.raw` | Image produced by mkosi (dm-verity hash tree embedded as a partition) |
| `code_commitment.txt` | Expected `code_commitment` (keccak256(RTMR3 after one extend)) |
| `manifest.json` | All of the above + their sha256 hashes + dm-verity `root_hash` |

## Auditor workflow

```sh
# Rebuild from source and compare every artifact byte-for-byte against
# the published reference.  Differences indicate either a build-env
# delta on the auditor's side, or that the reference was not produced
# from this source.
./verify-reproducible.sh
```

## Pinning protocol (release cut)

`build.sh` refuses to run while `Dockerfile.builder` still carries the
`PLACEHOLDER_REPLACE_AT_RELEASE_CUT` digest, so a release build cannot
silently produce non-reproducible artifacts. For local development before
the digest is pinned, opt out explicitly with `ALLOW_UNPINNED_BUILDER=1`
(emits a WARNING; the result is not reproducible).

At the time of v1.0 release:

1. Pin `Dockerfile.builder` `FROM debian@sha256:...` to the resolved
   digest of `debian:trixie-<release-date>-slim`. This clears the guard.
2. Pin `APT_SNAPSHOT_URL` to a snapshot.debian.org URL of the same date.
3. Cut the release tag and publish `manifest.json` alongside the image.
4. CI must run `verify-reproducible.sh` against every published tag.
