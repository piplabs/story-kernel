# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Story Kernel is a TEE (Intel SGX) client for Story Protocol's DKG system. It runs inside a Gramine SGX enclave to provide:
- **Pedersen DKG** — distributed key generation via `go.dedis.ch/kyber/v4`
- **TDH2 threshold decryption** — using Coinbase's `cb-mpc` C++ library (CGO)
- **Sealed storage** — keys sealed to enclave identity (SGX sealing)
- **CometBFT light client** — on-chain state verification

The binary is built with CGO against `cb-mpc` (C++), then signed and run under Gramine SGX.

## Build Commands

All builds require the `go_with_cpp.sh` wrapper which sets up CGO flags for `cb-mpc`:

```bash
# First-time: clone and build the cb-mpc C++ library
make setup-cbmpc

# Build the main binary
make build-with-cpp

# Build + generate Gramine manifest + SGX sign
make all-gramine

# Run all tests (non-SGX)
make test

# Run integration tests (non-SGX, faster iteration)
make integration-test

# Lint
make lint
```

### Compile integration test binary (for SGX runs)
```bash
CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh .cbmpc \
  go test -c -v ./integration/ -o ./build/integration-test
```

### Run a single integration test inside SGX
```bash
gramine-sgx integration-test -test.v -test.run "^TestName$"
```

### Run prioritized test suites
```bash
./scripts/run_p0_tests.sh   # Security boundary + core DKG/TDH2
./scripts/run_p1_tests.sh   # Production reliability (idempotency, fault tolerance, resharing)
./scripts/run_p2_tests.sh   # Robustness: edge cases, secondary validation
```

## Architecture

```
cmd/           — CLI entry point (cobra)
server/        — gRPC server setup and listener
service/       — DKG business logic (GenerateAndSealKey, GenerateDeals, ProcessDeals,
                  ProcessResponses, FinalizeDKG, PartialDecryptTDH2)
store/         — Sealed key storage (SGX sealing via enclave package)
enclave/       — SGX sealing/unsealing, code commitment (MRENCLAVE)
story/         — CometBFT light client, on-chain query client
config/        — YAML/env config loading
crypto/        — Ed25519 key helpers, secp256k1 wrappers
types/pb/v0/   — Protobuf-generated types
integration/   — Integration tests (DKG cluster simulation)
```

## DKG Protocol State Machine

The full flow per round:

1. `GenerateAndSealKey` — generates Ed25519 keypair, seals it to disk, returns DKG public key
2. `GenerateDeals` — builds `DistKeyGenerator`, generates encrypted deals for all peers
3. `ProcessDeals` — processes incoming deals, persists DKG state to disk, returns responses
4. `ProcessResponses` — processes all peer responses, finalizes deal verification
5. `FinalizeDKG` — extracts `DistKeyShare`, seals it, returns `global_pub_key`
6. `PartialDecryptTDH2` — loads sealed share, computes partial decryption, returns partial + pub share

**Resharing** (key rotation): old committee calls `GenerateDeals(IsResharing=true)` using the previous round's DKG state. New committee calls `ProcessDeals/ProcessResponses/FinalizeDKG(IsResharing=true)`. The `global_pub_key` is preserved across resharing rounds.

## Key Subtleties

**`CachePID` is skipped for resharing dealers.** In `GenerateDeals`, `CachePID` loads the node's round-N Ed25519 key to cache its 1-based PID for later `PartialDecryptTDH2` use. Old-committee nodes in a resharing round never called `GenerateAndSealKey` for the new round, so they have no new-round key on disk. The call is guarded with `if !req.GetIsResharing()`.

**DKG state survives restart.** `ProcessDeals` persists deals to disk via `DKGStore`. On the next call to `GetInitDKG`, `rebuildInitDKG` loads the persisted `DKGState`, reconstructs a `DistKeyGenerator`, and replays messages — so a node can complete `ProcessResponses`/`FinalizeDKG` after a crash. **Critical invariant**: `rebuildInitDKG` is only called when `HasDKGState` returns `true`, which requires both `Threshold != 0` and `len(PubKeys) != 0` on disk. `AddDeals` alone does NOT satisfy this — `Threshold` and `PubKeys` must be written via `SetInitDKGState` (called by `GetInitDKG` on first initialization) before any deals are persisted. If this invariant is broken, restart recovery silently falls back to `buildInitDKG` (fresh DKG, no deals replayed).

**`RoundCtxCache` must be invalidated after registration changes in tests.** `GenerateAndSealKey` calls `GetOrLoadRoundContext`, which caches the round's `SortedPubKeys` from `GetAllVerifiedDKGRegistrations`. In integration tests, if `GenerateAndSealKey` is called before `SetRegistrationsByRound` for that round, the cache gets populated with stale registrations (mock falls back to current primary registrations). Always reset `RoundCtxCache` on all affected servers after updating registrations via `SetRegistrationsByRound`. This applies to both old-committee and new-committee server sets in resharing tests.

**`buildResharingPrevDKG` cache routing.** When generating deals for a resharing round N+1, the node needs the previous round N DKG. If round N was itself a resharing result (`GetIsResharing()==true`), the state lives in `ResharingNextCache`; if round N was an initial DKG (`false`), it's in `InitDKGCache`. The `latest` active network's `IsResharing` flag drives which path is taken.

**SGX code commitment** = MRENCLAVE hash of the binary. Reproducible builds require `-trimpath -buildvcs=false -ldflags="-buildid="` (injected automatically by `go_with_cpp.sh` for `go build` invocations).

## Dependencies

- `go.dedis.ch/kyber/v4` — Pedersen DKG, Ed25519 suite
- `github.com/coinbase/cb-mpc` — TDH2 encrypt/decrypt/combine (C++ via CGO)
- `github.com/cometbft/cometbft` — light client for on-chain verification
- `github.com/ethereum/go-ethereum` — secp256k1, ECDSA
- `google.golang.org/grpc` — RPC transport
- `github.com/gramine` (runtime) — SGX enclave execution

## Integration Test Maintenance Policy

When reviewing colleague comments (e.g., from the Notion page [DKG integration test plan](https://www.notion.so/31a051299a5480eba11cd639d5fe2a11)) that suggest missing test cases:

1. **Add implementable cases** to the integration test files on the current branch.
2. **Update `docs/TestCases_review.md`** (in Chinese) with new test case entries, updated counts, and a "cannot implement" section with reasons.
3. **Update test scripts** (`integration/scripts/run_p0_tests.sh`, `run_p1_tests.sh`, `run_p2_tests.sh`) to include new test names in the appropriate priority tier.

## Git Commit Rules

- **Do NOT add `Co-Authored-By` lines** in commit messages. Commits should not include AI attribution.

## Git Push Rules

- **NEVER push the `docs/` directory to remote.** It is in `.gitignore` and should remain local-only. The `docs/` folder contains internal review documents (`TestCases_review.md`, etc.) that are not part of the shipped codebase.
- **NEVER push `.claude/` or `.vscode/` directories to remote.**
