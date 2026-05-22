package enclave

// Quoter generates remote-attestation quotes that embed caller-supplied
// userData into the quote's report-data field.
type Quoter interface {
	// GetRemoteQuote returns a TEE quote with userData embedded. userData
	// must not exceed the platform's report-data size (SGX: 64B; TDX: 64B).
	// Implementations zero-pad shorter inputs.
	GetRemoteQuote(userData []byte) ([]byte, error)
}
