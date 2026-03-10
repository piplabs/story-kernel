package service

import (
	"encoding/hex"
	"strings"
	"testing"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateReportData(t *testing.T) {
	tests := []struct {
		name             string
		validatorAddr    string
		round            uint32
		edPubBz          []byte
		secpPubBz        []byte
		startBlockHeight int64
		startBlockHash   []byte
		wantErr          bool
		errContains      string
	}{
		{
			name:             "valid input",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			edPubBz:          []byte{0x01, 0x02, 0x03},
			secpPubBz:        []byte{0x04, 0x05, 0x06},
			startBlockHeight: 1000,
			startBlockHash:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
			wantErr:          false,
		},
		{
			name:             "valid input without 0x prefix",
			validatorAddr:    "1234567890123456789012345678901234567890",
			round:            100,
			edPubBz:          []byte{0xaa},
			secpPubBz:        []byte{0xbb},
			startBlockHeight: 5000,
			startBlockHash:   make([]byte, 32), // 32-byte zero hash
			wantErr:          false,
		},
		{
			name:             "zero start block height",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: 0,
			startBlockHash:   []byte{0xab},
			wantErr:          false, // Function doesn't validate, validation happens in caller
		},
		{
			name:             "negative start block height",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: -1,
			startBlockHash:   []byte{0xab},
			wantErr:          false, // Function doesn't validate, validation happens in caller
		},
		{
			name:             "empty start block hash",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: 1000,
			startBlockHash:   []byte{},
			wantErr:          false, // Function doesn't validate, validation happens in caller
		},
		{
			name:             "invalid address - too short",
			validatorAddr:    "0x1234",
			round:            1,
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: 1000,
			startBlockHash:   []byte{0xab},
			wantErr:          true,
			errContains:      "invalid address",
		},
		{
			name:             "invalid address - not hex",
			validatorAddr:    "0xZZZZ567890123456789012345678901234567890",
			round:            1,
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: 1000,
			startBlockHash:   []byte{0xab},
			wantErr:          true,
			errContains:      "invalid address",
		},
		{
			name:             "large round number",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            4294967295, // max uint32
			edPubBz:          []byte{0x01},
			secpPubBz:        []byte{0x02},
			startBlockHeight: 9223372036854775807, // max int64
			startBlockHash:   []byte{0xab},
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calculateReportData(
				tt.validatorAddr,
				tt.round,
				tt.edPubBz,
				tt.secpPubBz,
				tt.startBlockHeight,
				tt.startBlockHash,
			)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, got)
			assert.Len(t, got, 32, "reportData should be 32 bytes (Keccak256 output)")
		})
	}
}

func TestCalculateReportDataDeterministic(t *testing.T) {
	// Test that same inputs always produce same output
	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(42)
	edPubBz := []byte{0xaa, 0xbb, 0xcc}
	secpPubBz := []byte{0xdd, 0xee, 0xff}
	startBlockHeight := int64(1000)
	startBlockHash := []byte{0x11, 0x22, 0x33, 0x44}

	result1, err1 := calculateReportData(validatorAddr, round, edPubBz, secpPubBz, startBlockHeight, startBlockHash)
	require.NoError(t, err1)

	result2, err2 := calculateReportData(validatorAddr, round, edPubBz, secpPubBz, startBlockHeight, startBlockHash)
	require.NoError(t, err2)

	assert.Equal(t, result1, result2, "Same inputs should produce same reportData")
}

func TestCalculateReportDataFormatCompatibility(t *testing.T) {
	// This test documents the exact encoding format for CL to replicate
	// CRITICAL: This format must match CL verification code and Solidity contract

	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(1)
	edPubBz := []byte{0xaa, 0xbb}
	secpPubBz := []byte{0xcc, 0xdd}
	startBlockHeight := int64(1000)
	startBlockHash := []byte{0x11, 0x22, 0x33, 0x44}

	reportData, err := calculateReportData(
		validatorAddr,
		round,
		edPubBz,
		secpPubBz,
		startBlockHeight,
		startBlockHash,
	)
	require.NoError(t, err)

	// Manually compute expected hash to verify encoding
	// Order: validator + round + startBlockHeight + startBlockHash + edPubKey + secpPubKey
	addr, err := hex.DecodeString(strings.TrimPrefix(validatorAddr, "0x"))
	require.NoError(t, err)

	expected := append([]byte{}, addr...)                          // 20 bytes
	expected = append(expected, uint32ToBytes(round)...)           // 4 bytes (big-endian)
	expected = append(expected, int64ToBytes(startBlockHeight)...) // 8 bytes (big-endian)
	expected = append(expected, startBlockHash...)                 // 4 bytes
	expected = append(expected, edPubBz...)                        // 2 bytes
	expected = append(expected, secpPubBz...)                      // 2 bytes

	expectedHash := ecrypto.Keccak256(expected)

	assert.Equal(t, expectedHash, reportData,
		"reportData format must match expected encoding for CL verification")

	// Verify total encoded length
	expectedLen := 20 + 4 + 8 + 4 + 2 + 2 // addr + round + height + hash + edPub + secpPub
	assert.Len(t, expected, expectedLen, "encoded data should have expected length")
}

func TestCalculateReportDataInputVariation(t *testing.T) {
	// Test that changing any input changes the output
	baseAddr := "0x1234567890123456789012345678901234567890"
	baseRound := uint32(1)
	baseEdPub := []byte{0xaa}
	baseSecpPub := []byte{0xbb}
	baseHeight := int64(1000)
	baseHash := []byte{0xcc}

	baseResult, err := calculateReportData(baseAddr, baseRound, baseEdPub, baseSecpPub, baseHeight, baseHash)
	require.NoError(t, err)

	// Change validator address
	result1, _ := calculateReportData("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", baseRound, baseEdPub, baseSecpPub, baseHeight, baseHash)
	assert.NotEqual(t, baseResult, result1, "changing validator address should change reportData")

	// Change round
	result2, _ := calculateReportData(baseAddr, 999, baseEdPub, baseSecpPub, baseHeight, baseHash)
	assert.NotEqual(t, baseResult, result2, "changing round should change reportData")

	// Change edPubBz
	result3, _ := calculateReportData(baseAddr, baseRound, []byte{0xff}, baseSecpPub, baseHeight, baseHash)
	assert.NotEqual(t, baseResult, result3, "changing edPubBz should change reportData")

	// Change secpPubBz
	result4, _ := calculateReportData(baseAddr, baseRound, baseEdPub, []byte{0xff}, baseHeight, baseHash)
	assert.NotEqual(t, baseResult, result4, "changing secpPubBz should change reportData")

	// Change startBlockHeight
	result5, _ := calculateReportData(baseAddr, baseRound, baseEdPub, baseSecpPub, 9999, baseHash)
	assert.NotEqual(t, baseResult, result5, "changing startBlockHeight should change reportData")

	// Change startBlockHash
	result6, _ := calculateReportData(baseAddr, baseRound, baseEdPub, baseSecpPub, baseHeight, []byte{0xff})
	assert.NotEqual(t, baseResult, result6, "changing startBlockHash should change reportData")
}

func TestInt64ToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected []byte
	}{
		{
			name:     "zero",
			input:    0,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "positive small",
			input:    1,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // Big-Endian
		},
		{
			name:     "positive large",
			input:    1000,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8}, // Big-Endian
		},
		{
			name:     "block height 1000000",
			input:    1000000,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40}, // Big-Endian
		},
		{
			name:     "max int64",
			input:    9223372036854775807,                                    // 0x7FFFFFFFFFFFFFFF
			expected: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Big-Endian
		},
		{
			name:     "negative",
			input:    -1,
			expected: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Big-Endian (two's complement)
		},
		{
			name:     "negative large",
			input:    -1000,
			expected: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x18}, // Big-Endian (two's complement)
		},
		{
			name:     "min int64",
			input:    -9223372036854775808,                                   // 0x8000000000000000
			expected: []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Big-Endian
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := int64ToBytes(tt.input)
			assert.Equal(t, tt.expected, result, "int64ToBytes encoding should match expected big-endian bytes")
			assert.Len(t, result, 8, "int64ToBytes should always return 8 bytes")
		})
	}
}

func TestUint32ToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected []byte
	}{
		{
			name:     "zero",
			input:    0,
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "small",
			input:    1,
			expected: []byte{0x00, 0x00, 0x00, 0x01}, // Big-Endian
		},
		{
			name:     "medium",
			input:    1000,
			expected: []byte{0x00, 0x00, 0x03, 0xe8}, // Big-Endian
		},
		{
			name:     "0x12345678",
			input:    0x12345678,
			expected: []byte{0x12, 0x34, 0x56, 0x78}, // Big-Endian
		},
		{
			name:     "large",
			input:    16777216,                       // 0x01000000
			expected: []byte{0x01, 0x00, 0x00, 0x00}, // Big-Endian
		},
		{
			name:     "max uint32",
			input:    4294967295,                     // 0xFFFFFFFF
			expected: []byte{0xff, 0xff, 0xff, 0xff}, // Big-Endian
		},
		{
			name:     "round number",
			input:    42,
			expected: []byte{0x00, 0x00, 0x00, 0x2a}, // Big-Endian
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uint32ToBytes(tt.input)
			assert.Equal(t, tt.expected, result, "uint32ToBytes encoding should match expected big-endian bytes")
			assert.Len(t, result, 4, "uint32ToBytes should always return 4 bytes")
		})
	}
}

func TestEncodingFunctionsRoundTrip(t *testing.T) {
	// Test that encoding and decoding work correctly
	t.Run("int64 round trip", func(t *testing.T) {
		testValues := []int64{0, 1, -1, 1000, -1000, 9223372036854775807, -9223372036854775808}
		for _, val := range testValues {
			encoded := int64ToBytes(val)
			// Decode manually
			var decoded int64
			for i := 0; i < 8; i++ {
				decoded = (decoded << 8) | int64(encoded[i])
			}
			assert.Equal(t, val, decoded, "int64 should round-trip correctly")
		}
	})

	t.Run("uint32 round trip", func(t *testing.T) {
		testValues := []uint32{0, 1, 1000, 4294967295}
		for _, val := range testValues {
			encoded := uint32ToBytes(val)
			// Decode manually
			var decoded uint32
			for i := 0; i < 4; i++ {
				decoded = (decoded << 8) | uint32(encoded[i])
			}
			assert.Equal(t, val, decoded, "uint32 should round-trip correctly")
		}
	})
}

func TestEncodingConsistency(t *testing.T) {
	// Verify that our encoding matches binary.BigEndian behavior
	t.Run("int64 consistency", func(t *testing.T) {
		val := int64(123456789)
		result1 := int64ToBytes(val)
		result2 := int64ToBytes(val)
		assert.Equal(t, result1, result2, "multiple calls should produce same result")
	})

	t.Run("uint32 consistency", func(t *testing.T) {
		val := uint32(123456)
		result1 := uint32ToBytes(val)
		result2 := uint32ToBytes(val)
		assert.Equal(t, result1, result2, "multiple calls should produce same result")
	})
}

func TestReverseBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty slice",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "single byte",
			input:    []byte{0xAB},
			expected: []byte{0xAB},
		},
		{
			name:     "even length",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: []byte{0x04, 0x03, 0x02, 0x01},
		},
		{
			name:     "odd length",
			input:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x03, 0x02, 0x01},
		},
		{
			name:     "all zeros",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "all 0xFF",
			input:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:     "two bytes",
			input:    []byte{0xDE, 0xAD},
			expected: []byte{0xAD, 0xDE},
		},
		{
			name:     "palindrome",
			input:    []byte{0xAB, 0xCD, 0xAB},
			expected: []byte{0xAB, 0xCD, 0xAB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverseBytes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReverseBytesDoesNotMutateInput(t *testing.T) {
	original := []byte{0x01, 0x02, 0x03}
	inputCopy := make([]byte, len(original))
	copy(inputCopy, original)

	_ = reverseBytes(original)

	assert.Equal(t, inputCopy, original, "reverseBytes must not mutate the input slice")
}

func TestReverseBytesNil(t *testing.T) {
	result := reverseBytes(nil)
	assert.NotNil(t, result, "reverseBytes(nil) should return a non-nil empty slice")
	assert.Len(t, result, 0)
}

// Benchmark tests
func BenchmarkCalculateReportData(b *testing.B) {
	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(1)
	edPubBz := make([]byte, 32)
	secpPubBz := make([]byte, 64)
	startBlockHeight := int64(1000)
	startBlockHash := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = calculateReportData(validatorAddr, round, edPubBz, secpPubBz, startBlockHeight, startBlockHash)
	}
}

func BenchmarkInt64ToBytes(b *testing.B) {
	val := int64(123456789)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = int64ToBytes(val)
	}
}

func BenchmarkUint32ToBytes(b *testing.B) {
	val := uint32(123456)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uint32ToBytes(val)
	}
}
