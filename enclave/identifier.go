package enclave

// Identifier exposes the running TEE's code commitment and supports
// length-agnostic comparison of an externally supplied code commitment to the
// running identity.
type Identifier interface {
	// GetSelfCodeCommitment returns the running enclave's code commitment.
	// SGX: 32B MRENCLAVE. TDX: 32B keccak256(RTMR3) (self-extended at boot
	// with SHA-384 of the kernel ELF).
	GetSelfCodeCommitment() ([]byte, error)

	// ValidateCodeCommitment compares an external code commitment against the
	// running enclave's via bytes.Equal (length-agnostic).
	ValidateCodeCommitment(codeCommitment []byte) error
}
