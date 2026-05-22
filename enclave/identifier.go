package enclave

// Identifier exposes the running TEE's measurement set and supports
// length-agnostic comparison of an externally supplied code commitment to the
// running identity.
type Identifier interface {
	// GetSelfIdentity returns the running enclave's full native identity.
	// SGX populates Type, CodeCommitment (32B MRENCLAVE), ProductID (2B
	// ISVPRODID). TDX populates Type, MRTD, RTMR0..3, and CodeCommitment as
	// the 32-byte hybrid-hook binary commitment keccak256(RTMR2).
	GetSelfIdentity() (*Identity, error)

	// GetSelfCodeCommitment returns the running enclave's code commitment.
	// SGX: 32B MRENCLAVE. TDX: 32B keccak256(RTMR2).
	GetSelfCodeCommitment() ([]byte, error)

	// ValidateCodeCommitment compares an external code commitment against the
	// running enclave's via bytes.Equal (length-agnostic).
	ValidateCodeCommitment(codeCommitment []byte) error
}
