package enclave

// This file collects the data types shared across the enclave package and its
// backend sub-packages (sgx, tdx, noop). Interfaces and dispatch primitives
// live in tee.go; narrow capability interfaces live in sealer.go, quoter.go,
// and identifier.go.

// IdentityType discriminates which fields of Identity are populated.
type IdentityType uint8

const (
	// IdentityUnknown is the zero value; not a valid backend identity.
	IdentityUnknown IdentityType = 0
	// IdentitySGX denotes an Intel SGX enclave (MRENCLAVE-based identity).
	IdentitySGX IdentityType = 1
	// IdentityTDX denotes an Intel TDX trust domain (MRTD + RTMR0..3 identity).
	IdentityTDX IdentityType = 2
)

// Identity is the platform-agnostic identity of a running TEE.
//
// Both backends contract `CodeCommitment` to a **32-byte** hybrid-hook value:
//   - SGX: MRENCLAVE.
//   - TDX direct: keccak256(RTMR3) — the binary half of the on-chain hybrid
//     hook commitment. RTMR3 is bound to the running Go binary by a one-shot
//     SHA-384 self-extend during TD bootstrap (see
//     `enclave/tdx/backend.go::extendBinaryMeasurementOnce`). The platform
//     half `keccak256(MRTD || RTMR0 || RTMR1 || RTMR2)` is derived and
//     verified entirely on chain by the TDXValidationHook against its
//     `approvedPlatforms` whitelist; the kernel never touches it.
//
// `hashFinalizeDKGResponse` consumes the 32-byte value directly (no further
// compression), and the chain stores it in `EnclaveTypeData.codeCommitment`
// (whitelisted via DKG.whitelistEnclaveType) and emits it in the
// `Finalized.codeCommitment` slot. Kernel-side comparisons use bytes.Equal.
//
// Native measurements (MRTD/RTMR0..3 for TDX, ProductID for SGX) remain
// populated for diagnostics and platform-commitment derivation only —
// backend-specific consumers can read them, but the platform-agnostic API
// surface only signs over `CodeCommitment`.
type Identity struct {
	Type           IdentityType
	CodeCommitment []byte
	ProductID      []byte
	MRTD           []byte
	RTMR0          []byte
	RTMR1          []byte
	RTMR2          []byte
	RTMR3          []byte
}
