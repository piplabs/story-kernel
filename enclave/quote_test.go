package enclave

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseQuoteFields_TooShort verifies that a quote shorter than minQuoteSize returns an error.
func TestParseQuoteFields_TooShort(t *testing.T) {
	t.Parallel()

	t.Run("empty quote", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := parseQuoteFields([]byte{})
		require.ErrorContains(t, err, "quote too short")
	})

	t.Run("one byte short of minimum", func(t *testing.T) {
		t.Parallel()
		quote := make([]byte, minQuoteSize-1)
		_, _, _, err := parseQuoteFields(quote)
		require.ErrorContains(t, err, "quote too short")
	})

	t.Run("exactly one byte", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := parseQuoteFields([]byte{0x01})
		require.ErrorContains(t, err, "quote too short")
	})
}

// TestParseQuoteFields_MinimumSize verifies that a quote of exactly minQuoteSize is parsed.
func TestParseQuoteFields_MinimumSize(t *testing.T) {
	t.Parallel()

	// Build a synthetic quote of exactly minQuoteSize bytes.
	// Fill specific regions with recognizable marker bytes.
	quote := make([]byte, minQuoteSize)

	// Place marker bytes at code commitment region (offset 112, 32 bytes)
	for i := 0; i < codeCommitmentSize; i++ {
		quote[codeCommitmentOffset+i] = 0xAA
	}

	// Place marker bytes at product ID region (offset 304, 2 bytes)
	quote[isvProdIDOffset] = 0xBB
	quote[isvProdIDOffset+1] = 0xCC

	// Place marker bytes at report data region (offset 368, 64 bytes)
	for i := 0; i < reportDataSize; i++ {
		quote[reportDataOffset+i] = 0xDD
	}

	codeCommitment, productID, reportData, err := parseQuoteFields(quote)
	require.NoError(t, err)

	// Verify code commitment is extracted correctly
	require.Len(t, codeCommitment, codeCommitmentSize)
	for _, b := range codeCommitment {
		require.Equal(t, byte(0xAA), b)
	}

	// Verify product ID is extracted correctly
	require.Len(t, productID, isvProdIDSize)
	require.Equal(t, byte(0xBB), productID[0])
	require.Equal(t, byte(0xCC), productID[1])

	// Verify report data is extracted correctly
	require.Len(t, reportData, reportDataSize)
	for _, b := range reportData {
		require.Equal(t, byte(0xDD), b)
	}
}

// TestParseQuoteFields_LargerQuote verifies parsing works with a quote larger than minimum.
func TestParseQuoteFields_LargerQuote(t *testing.T) {
	t.Parallel()

	// Build a quote larger than minimum (e.g., 1000 bytes)
	quote := make([]byte, 1000)

	// Set recognizable bytes at the code commitment region
	for i := 0; i < codeCommitmentSize; i++ {
		quote[codeCommitmentOffset+i] = byte(i + 1)
	}

	codeCommitment, productID, reportData, err := parseQuoteFields(quote)
	require.NoError(t, err)

	// Verify sizes
	require.Len(t, codeCommitment, codeCommitmentSize)
	require.Len(t, productID, isvProdIDSize)
	require.Len(t, reportData, reportDataSize)

	// Verify code commitment content
	for i, b := range codeCommitment {
		require.Equal(t, byte(i+1), b, "code commitment byte %d mismatch", i)
	}
}

// TestParseQuoteFields_IsolatesRegions verifies that each parsed region is independent.
func TestParseQuoteFields_IsolatesRegions(t *testing.T) {
	t.Parallel()

	quote := make([]byte, minQuoteSize)

	// Set distinct values in each region
	for i := 0; i < codeCommitmentSize; i++ {
		quote[codeCommitmentOffset+i] = 0x11
	}
	for i := 0; i < isvProdIDSize; i++ {
		quote[isvProdIDOffset+i] = 0x22
	}
	for i := 0; i < reportDataSize; i++ {
		quote[reportDataOffset+i] = 0x33
	}

	codeCommitment, productID, reportData, err := parseQuoteFields(quote)
	require.NoError(t, err)

	// Verify each region contains only its own value
	require.True(t, bytes.Equal(codeCommitment, bytes.Repeat([]byte{0x11}, codeCommitmentSize)))
	require.True(t, bytes.Equal(productID, bytes.Repeat([]byte{0x22}, isvProdIDSize)))
	require.True(t, bytes.Equal(reportData, bytes.Repeat([]byte{0x33}, reportDataSize)))
}

// TestParseQuoteFields_ReturnsNewSlices verifies that parsed fields are independent copies.
func TestParseQuoteFields_ReturnsNewSlices(t *testing.T) {
	t.Parallel()

	quote := make([]byte, minQuoteSize)
	for i := 0; i < codeCommitmentSize; i++ {
		quote[codeCommitmentOffset+i] = 0x55
	}

	codeCommitment, _, _, err := parseQuoteFields(quote)
	require.NoError(t, err)

	// Modifying the original quote should not affect the returned slice
	for i := 0; i < codeCommitmentSize; i++ {
		quote[codeCommitmentOffset+i] = 0xFF
	}

	// codeCommitment should still contain 0x55 (it is a copy)
	for _, b := range codeCommitment {
		require.Equal(t, byte(0x55), b, "codeCommitment must be an independent copy of the quote data")
	}
}

// TestGetRemoteQuote_UserDataTooLong verifies that user data exceeding 64 bytes is rejected.
func TestGetRemoteQuote_UserDataTooLong(t *testing.T) {
	t.Parallel()

	// 65 bytes exceeds the 64-byte reportDataSize limit
	longData := make([]byte, reportDataSize+1)
	_, err := GetRemoteQuote(longData)
	require.ErrorContains(t, err, "user data exceeds")
}

// TestGetRemoteQuote_ExactLimitAccepted verifies that exactly 64 bytes would pass size check.
// Note: The actual Gramine file write will fail outside SGX, but the size validation succeeds.
func TestGetRemoteQuote_ExactLimitAccepted(t *testing.T) {
	t.Parallel()

	exactData := make([]byte, reportDataSize)
	_, err := GetRemoteQuote(exactData)
	// Should fail due to Gramine pseudo-file not being available outside SGX,
	// not due to input validation.
	if err != nil {
		require.NotContains(t, err.Error(), "user data exceeds",
			"exact-limit data should not trigger the size validation error")
	}
}

// TestConstants_QuoteOffsets verifies that quote layout constants are consistent.
func TestConstants_QuoteOffsets(t *testing.T) {
	t.Parallel()

	// Verify calculated offsets match expected values
	require.Equal(t, 112, codeCommitmentOffset, "code commitment offset must be 112")
	require.Equal(t, 304, isvProdIDOffset, "ISV product ID offset must be 304")
	require.Equal(t, 368, reportDataOffset, "report data offset must be 368")

	// Verify minimum quote size covers the report data region
	expectedMinSize := reportDataOffset + reportDataSize
	require.Equal(t, 432, minQuoteSize, "minimum quote size must be 432")
	require.Equal(t, expectedMinSize, minQuoteSize)

	// Verify sizes
	require.Equal(t, 32, codeCommitmentSize)
	require.Equal(t, 2, isvProdIDSize)
	require.Equal(t, 64, reportDataSize)
}
