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

// Identity is the platform-agnostic measurement set for a running TEE.
//
// SGX populates Type, CodeCommitment (32B MRENCLAVE), ProductID (2B ISVPRODID).
// TDX populates Type, MRTD (48B), RTMR0..3 (each 48B), and CodeCommitment is
// the native concatenation MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3 (240B).
// Kernel-side identity comparisons use bytes.Equal and are length-agnostic;
// the on-chain side independently parses raw quotes via the per-TEE-type
// ValidationHook contract and is unaffected by this kernel-internal shape.
//
// Fields not relevant to the platform are nil/empty.
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

// EnclaveInfo is the legacy SGX-shaped self-info structure preserved for
// callers that consume MRENCLAVE + ISVPRODID directly.
//
// Deprecated: Prefer Identity via TEE.GetSelfIdentity. EnclaveInfo cannot
// represent a TDX identity correctly — UniqueID would hold a 240-byte
// concatenation, breaking the documented 32-byte SGX contract. Existing
// callers that consume this shape via GetSelfEnclaveInfo continue to work
// in SGX builds; in TDX builds GetSelfEnclaveInfo projects a 240-byte
// UniqueID, which most legacy callers will reject.
type EnclaveInfo struct {
	ProductID []byte
	UniqueID  []byte
}
