# Threat model

This document is the source of truth for *why every part of the
launcher exists*. Every other launcher document and every component
justifies itself against this model. If a component does not address
a threat listed here, it should be removed.

## Assets to protect

| Asset | Why it matters |
|---|---|
| **DKG key share** held by each validator | If extracted from one validator, combined with t-1 others off-chain ⇒ full CDR decryption |
| **Validator binary identity** | If a modified binary runs in place of the published one, it can bypass any on-chain access check |
| **Light-client trust root** (chain ID, validator set, genesis) | If tampered with, the validator accepts spoofed chain state and acts on fake authorizations |
| **Boot chain measurements** (MRTD, RTMR0..2) | If they can be lied about, governance approval of the platform is meaningless |

## Threat actors

| Actor | What they control | What they want |
|---|---|---|
| **Cloud / hypervisor** | All host hardware below the TD | Read TD memory, observe DKG state |
| **Operator with root inside TD** | Everything inside the TD that is not protected by TDX hardware | Extract key share, modify binary behavior |
| **Colluding subset of validators** (t of n) | Their own key shares + a private side channel | Reconstruct CDR plaintext off-chain, undetectable on-chain |
| **Cross-chain adversary** | Ability to spin up a fork chain | Trick a validator into honoring a fake "authorize" event |
| **Sybil attacker** | Stake on chain | Get a non-conforming binary onto the active committee |

## Numbered threats and defenses

### (A) Cloud / hypervisor reads TD memory

**Attack:** GCP, AWS, Azure, etc. snapshot the TD's RAM during a live migration or read it via SMM/DMA paths. Plaintext key shares fall out.

**Defense:** TDX memory encryption (hardware). Inherited from the TDX architecture — the launcher does not add anything specific here, but image hardening prevents accidental egress paths (no swap, no core dumps, no `/dev/mem`).

**Tested by:** N/A at launcher level — TDX hardware guarantee.

### (B) Operator with root inside TD modifies behavior

**Attack:** The operator who owns the validator VM logs into the TD, attaches `gdb` to story-kernel, dumps memory, or replaces `/usr/local/bin/story-kernel` with a modified ELF.

**Defenses:**
- `dm-verity` makes the rootfs read-only and integrity-checked at block-read time — any write triggers kernel panic.
- `kernel.yama.ptrace_scope=3` blocks all ptrace (no `gdb` attach).
- No SSH daemon, no serial console after early boot, all getty units masked.
- `/dev/mem`, `/dev/kmem`, `/dev/port` unavailable.
- The `story-kernel` user has `nologin` and no writable paths outside `/var/lib/story-kernel`.

> **Note on `lockdown`/module-signing:** the custom kernel is built keyless
> (`CONFIG_MODULE_SIG=n`, `SECURITY_LOCKDOWN_LSM` disabled) for reproducibility
> without a private key (see `gcp-tdx-deployment.md` §1 and `../kernel/`). This is
> not load-bearing for (B): the gap between operator-root and the sealed key is
> closed by **no root entry path** (no sshd/getty, root locked) + dm-verity + the
> PCR-bound seal — not by lockdown or signed modules (which only restrict an
> *already-root* process that cannot be reached here). Aggressive memory-hardening
> cmdline flags (`init_on_alloc`, `slab_nomerge`, …) are staged but kept off until
> each is bisected against GCP TDX boot (`gcp-tdx-deployment.md` §2).

**Tested by:** `launcher/tests/hardening_test.sh` (on a booted image).

### (B') t-of-n validator off-chain collusion

**Attack:** Threshold (t) of n validator operators each extract their plaintext DKG share, share off-chain (Discord/Telegram), compute partial decryptions for any CDR ciphertext, reconstruct plaintext. Undetectable on chain — no slashing possible.

**Defenses:**
- Key share is *sealed* against `PolicyPCR(PCR 7, 11, 12)` (PCR 7 = Secure Boot policy, PCR 11 = UKI/dm-verity rootfs, PCR 12 = `SHA-256(story-kernel ELF)`, self-extended at boot). Only the exact boot + ELF that produced the sealing can unseal it; no field of the (operator-supplied) node config enters the seal policy.
- On GCP confidential VMs the seal uses the CVM's measured vTPM (`/dev/tpmrm0`); the in-TD `swtpm` path is neutralized on GCP because the CVM always exposes a built-in `tpm_tis` vTPM at `/dev/tpm0` (see `gcp-tdx-deployment.md` §3.1). A wrong boot/VM context fails the unseal policy — a sealed blob cannot be replayed on another VM.
- (B) defenses also apply — without root access inside the running TD, the operator cannot scrape the unsealed share from process memory.

**Why this is the most important defense:** (B') is the canonical APT against Story CDR. Every other security property only matters if (B') is blocked. **The entire launcher infrastructure exists primarily to make (B') impossible.**

**Tested by:** `launcher/tests/sealing_test.sh` (requires real TDX hardware).

### (C) Fork-chain spoofing of the light client

**Attack:** Attacker spins up a chain that looks superficially like Story (same genesis, similar validators) but with fake authorizations naming `pk_attacker` as a reader. If the validator's light client accepts this state, the validator generates decryption material for the attacker.

**Defenses:**
- The light-client config (chain ID, RPC/witness endpoints, trusted block) is **operator-supplied via instance metadata**, not baked into the rootfs. This is deliberate (it keeps the commitments stable across chains; see `gcp-tdx-deployment.md` §4) and does **not** enable this attack, because the defenses below do not rely on the config being immutable.
- The verified query client in story-kernel validates every chain query (Merkle proofs against the followed header) and persists trusted light-client state in the **sealed** DB; a conflicting header from a fork is detected. `witness_addrs` is required to be ≥ 2 so a single malicious primary is caught.
- The TDX quote's `report_data` binds the followed chain's `startBlockHeight`/`startBlockHash` (+ round, validator, keys). A quote produced against a forged chain is **re-checked by the consensus client against real-chain state** and rejected — so an operator pointing the node at a fork cannot register or finalize on the real chain; at worst they DoS their own node.
- `code_commitment = keccak256(RTMR3)` binds the on-chain whitelist to the exact light-client implementation. A modified verified-query function produces a different RTMR3 and is rejected by `TDXValidationHook.approvedBinary[]`.

**Residual (config governance, not a TEE break):** because the config is mutable metadata, re-pointing a whitelisted validator leaves no on-chain trace (vs a baked config, which required a rebuild → new `platform_commitment` → visible re-whitelist). Mitigate operationally: restrict `compute.instances.setMetadata` IAM and log the config hash. It cannot extract the sealed key or forge real-chain registration.

**Tested by:** Off-chain audit of the verified query client; end-to-end on devnet (forged config cannot register on the real chain — `report_data` start-block mismatch).

### (D) Sybil — fake validator joins committee

**Attack:** Attacker registers a validator running their own modified code (or no TDX at all) and tries to join the active DKG committee.

**Defenses:**
- `TDXValidationHook` on chain checks `approvedPlatform[platform_commitment]` and `approvedBinary[code_commitment]` against governance-approved values.
- `platform_commitment = keccak256(MRTD || RTMR0 || RTMR1 || RTMR2)` requires a real TDX quote from an approved firmware vintage + bootloader + kernel + cmdline.
- `code_commitment = keccak256(RTMR3)` requires the exact published `story-kernel` ELF (RTMR3 self-extended at boot).

**Tested by:** End-to-end registration test on devnet (`launcher/out/manifest.json` ⇒ approve via governance ⇒ register-tx).

## Out-of-scope threats

- **Cryptographic protocol bugs** — handled by separate DKG/TDH2 audits, not by the launcher.
- **Side-channel attacks on TDX hardware** (rowhammer, etc.) — Intel's responsibility; would invalidate the entire trust model.
- **Compromise of the chain validator set** at protocol level — handled by Story consensus security; orthogonal.
- **Reader-side key compromise** (a CDR reader leaks their plaintext after receiving it) — by definition outside the launcher's control. CDR confidentiality terminates at the reader.

## Defense matrix (one row per threat, one column per launcher component)

| | `mkosi` | `initrd` | `boot` | `attestation` | `hardening` | `build` |
|---|---|---|---|---|---|---|
| (A) | — | — | — | — | partial | — |
| (B) | partial | partial | full (verity) | — | full | partial |
| (B') | full (sealing) | partial | full | full | partial | partial |
| (C) | — | — | partial | full (RTMR3) | — | — |
| (D) | partial | — | full | full | — | full |

"Full" = the named component is the primary defense; "partial" = it
contributes but is not load-bearing alone; "—" = does not address.

## Change protocol

Any change to this document requires a corresponding change to the
governance-approved `platform_commitment` and/or `code_commitment`,
because the threat model is what the on-chain whitelist *enforces*.
