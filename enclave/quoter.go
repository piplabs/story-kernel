package enclave

// Quoter generates remote-attestation quotes that embed caller-supplied
// userData into the quote's binding field. The exact placement is
// backend-specific; callers do not need to know which slot is used
// because every active deployment binds userData somewhere inside the
// cryptographically signed envelope.
type Quoter interface {
	// GetRemoteQuote returns a TEE quote with userData embedded.
	// userData must not exceed the platform's binding-field size (SGX:
	// 64B; TDX: 64B). Implementations zero-pad shorter inputs.
	//
	// Wire format and binding placement:
	//
	//   Backend │ Where userData lands               │ Wire format
	//   ────────┼───────────────────────────────────┼──────────────
	//   SGX     │ SGX report_data (64B padded)      │ raw EREPORT
	//   TDX     │ V4.report_data (64B padded)       │ raw V4 quote
	//
	// The on-chain validation hook compares the leading 32 bytes of
	// report_data against keccak256(EnclaveInstanceData).
	GetRemoteQuote(userData []byte) ([]byte, error)
}
