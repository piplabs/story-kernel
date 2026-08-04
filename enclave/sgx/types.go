package sgx

// EnclaveInfo is the SGX backend's self-info: MRENCLAVE (UniqueID) and
// ISVPRODID (ProductID) of the running enclave. It backs the process-wide
// self-info cache in quote.go.
type EnclaveInfo struct {
	ProductID []byte
	UniqueID  []byte
}
