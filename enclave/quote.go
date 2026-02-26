package enclave

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

// Gramine attestation pseudo-filesystem paths
// See: https://gramine.readthedocs.io/en/latest/attestation.html
const (
	userReportDataPath = "/dev/attestation/user_report_data"
	quotePath          = "/dev/attestation/quote"
)

// Cached self enclave info to avoid repeated quote generation.
var (
	selfEnclaveOnce sync.Once
	selfEnclaveInfo *EnclaveInfo
	errSelfEnclave  error
)

// Report Body: 384 bytes (starts at offset 48).
const (
	quoteHeaderSize  = 48
	reportBodyOffset = quoteHeaderSize

	// Offsets within Report Body.
	codeCommitmentOffsetInBody = 64  // CPUSVN(16) + MISCSELECT(4) + Reserved(28) + ATTRIBUTES(16)
	isvProdIDOffsetInBody      = 256 // ... + CodeCommitment(32) + Reserved(32) + MRSIGNER(32) + Reserved(96)
	reportDataOffsetInBody     = 320 // ... + ISVPRODID(2) + ISVSVN(2) + Reserved(60)

	// Absolute offsets in quote.
	codeCommitmentOffset = reportBodyOffset + codeCommitmentOffsetInBody // 112
	isvProdIDOffset      = reportBodyOffset + isvProdIDOffsetInBody      // 304
	reportDataOffset     = reportBodyOffset + reportDataOffsetInBody     // 368

	// Sizes.
	codeCommitmentSize = 32
	isvProdIDSize      = 2
	reportDataSize     = 64

	minQuoteSize = reportDataOffset + reportDataSize // 432
)

type EnclaveInfo struct {
	ProductID []byte
	UniqueID  []byte
}

// GetRemoteQuote generates an SGX quote with the given user data using Gramine's
// /dev/attestation interface. userData must be <= 64 bytes.
func GetRemoteQuote(userData []byte) ([]byte, error) {
	if len(userData) > reportDataSize {
		return nil, fmt.Errorf("user data exceeds %d bytes", reportDataSize)
	}

	// Pad user data to 64 bytes
	padded := make([]byte, reportDataSize)
	copy(padded, userData)

	// Write user report data to Gramine pseudo-file
	if err := os.WriteFile(userReportDataPath, padded, 0); err != nil {
		return nil, fmt.Errorf("failed to write user_report_data: %w", err)
	}

	// Read the SGX quote from Gramine pseudo-file
	quote, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote: %w", err)
	}

	return quote, nil
}

// parseQuoteFields extracts code commitment, ProductID, and ReportData from an SGX quote.
func parseQuoteFields(quote []byte) (codeCommitment, productID, reportData []byte, err error) {
	if len(quote) < minQuoteSize {
		return nil, nil, nil, fmt.Errorf("quote too short: %d < %d", len(quote), minQuoteSize)
	}

	codeCommitment = make([]byte, codeCommitmentSize)
	copy(codeCommitment, quote[codeCommitmentOffset:codeCommitmentOffset+codeCommitmentSize])

	productID = make([]byte, isvProdIDSize)
	copy(productID, quote[isvProdIDOffset:isvProdIDOffset+isvProdIDSize])

	reportData = make([]byte, reportDataSize)
	copy(reportData, quote[reportDataOffset:reportDataOffset+reportDataSize])

	return codeCommitment, productID, reportData, nil
}

func GetSelfEnclaveInfo() (*EnclaveInfo, error) {
	selfEnclaveOnce.Do(func() {
		// Generate a quote with dummy data to get our own enclave info
		quote, err := GetRemoteQuote([]byte{0})
		if err != nil {
			errSelfEnclave = fmt.Errorf("failed to get self quote: %w", err)

			return
		}

		codeCommitment, productID, _, err := parseQuoteFields(quote)
		if err != nil {
			errSelfEnclave = fmt.Errorf("failed to parse self quote: %w", err)

			return
		}

		selfEnclaveInfo = &EnclaveInfo{
			ProductID: productID,
			UniqueID:  codeCommitment,
		}
	})

	if errSelfEnclave != nil {
		return nil, errSelfEnclave
	}

	return selfEnclaveInfo, nil
}

func GetSelfCodeCommitment() ([]byte, error) {
	selfEnclave, err := GetSelfEnclaveInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get self enclave info: %w", err)
	}

	return selfEnclave.UniqueID, nil
}

func ValidateCodeCommitment(codeCommitment []byte) error {
	selfCodeCommitment, err := GetSelfCodeCommitment()
	if err != nil {
		return fmt.Errorf("failed to get code commitment of enclave: %w", err)
	}

	if !bytes.Equal(codeCommitment, selfCodeCommitment) {
		return fmt.Errorf("code commitment mismatch, expected %s, but got %s", hex.EncodeToString(selfCodeCommitment), hex.EncodeToString(codeCommitment))
	}

	return nil
}
