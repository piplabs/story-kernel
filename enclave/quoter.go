package enclave

// Quoter generates remote-attestation quotes that embed caller-supplied
// userData into the quote's binding field. The exact placement is
// backend- and vendor-specific; callers do not need to know which slot
// is used because every active deployment binds userData somewhere
// inside the cryptographically signed envelope.
type Quoter interface {
	// GetRemoteQuote returns a TEE quote with userData embedded.
	// userData must not exceed the platform's binding-field size (SGX:
	// 64B; TDX: 64B). Implementations zero-pad shorter inputs.
	//
	// Wire format and binding placement matrix:
	//
	//   Backend │ Vendor    │ Where userData lands               │ Wire format
	//   ────────┼───────────┼───────────────────────────────────┼──────────────────
	//   SGX     │ (n/a)     │ SGX report_data (64B padded)      │ raw EREPORT
	//   TDX     │ direct    │ V4.report_data (64B padded)       │ raw V4 quote
	//   TDX     │ paravisor │ TPMS_ATTEST.qualifyingData (≤64B) │ STBN bundle
	//
	// On a paravisor-mediated TDX guest, V4.report_data is
	// paravisor-locked to SHA256(VariableData) at boot, so userData
	// cannot land there; instead, an AK-signed TPM2_Quote binds
	// userData via qualifyingData inside a Path-B "STBN" bundle that
	// wraps V4 || TPMS_ATTEST || TPMT_SIGNATURE || AK_pub_DER. The
	// on-chain verifier dispatches by the 4-byte STBN magic at offset
	// 0; absent that magic the quote is treated as raw EREPORT (SGX)
	// or raw V4 (TDX direct) and the leading 32 bytes of report_data
	// are compared to keccak256(EnclaveInstanceData).
	//
	// See enclave/tdx/platform/bundle.go for the bundle wire format.
	GetRemoteQuote(userData []byte) ([]byte, error)
}
