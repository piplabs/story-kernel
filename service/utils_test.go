package service

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateReportData(t *testing.T) {
	tests := []struct {
		name           string
		round          uint32
		validatorAddr  string
		enclaveType    [32]byte
		enclaveCommKey []byte
		dkgPubKey      []byte
		wantErr        bool
		errContains    string
	}{
		{
			name:           "valid input",
			round:          1,
			validatorAddr:  "0x1234567890123456789012345678901234567890",
			enclaveType:    [32]byte{0x01},
			enclaveCommKey: []byte{0x04, 0x05, 0x06},
			dkgPubKey:      []byte{0x01, 0x02, 0x03},
			wantErr:        false,
		},
		{
			name:           "valid input without 0x prefix",
			round:          100,
			validatorAddr:  "1234567890123456789012345678901234567890",
			enclaveType:    [32]byte{0xaa, 0xbb},
			enclaveCommKey: []byte{0xbb},
			dkgPubKey:      []byte{0xaa},
			wantErr:        false,
		},
		{
			name:           "invalid address - too short",
			round:          1,
			validatorAddr:  "0x1234",
			enclaveType:    [32]byte{0x01},
			enclaveCommKey: []byte{0x02},
			dkgPubKey:      []byte{0x01},
			wantErr:        true,
			errContains:    "invalid address",
		},
		{
			name:           "invalid address - not hex",
			round:          1,
			validatorAddr:  "0xZZZZ567890123456789012345678901234567890",
			enclaveType:    [32]byte{0x01},
			enclaveCommKey: []byte{0x02},
			dkgPubKey:      []byte{0x01},
			wantErr:        true,
			errContains:    "invalid address",
		},
		{
			name:           "large round number",
			round:          4294967295, // max uint32
			validatorAddr:  "0x1234567890123456789012345678901234567890",
			enclaveType:    [32]byte{0xff},
			enclaveCommKey: []byte{0x02},
			dkgPubKey:      []byte{0x01},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calculateReportData(
				tt.round,
				tt.validatorAddr,
				tt.enclaveType,
				tt.enclaveCommKey,
				tt.dkgPubKey,
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
	round := uint32(42)
	validatorAddr := "0x1234567890123456789012345678901234567890"
	enclaveType := [32]byte{0x01, 0x02}
	enclaveCommKey := []byte{0xdd, 0xee, 0xff}
	dkgPubKey := []byte{0xaa, 0xbb, 0xcc}

	result1, err1 := calculateReportData(round, validatorAddr, enclaveType, enclaveCommKey, dkgPubKey)
	require.NoError(t, err1)

	result2, err2 := calculateReportData(round, validatorAddr, enclaveType, enclaveCommKey, dkgPubKey)
	require.NoError(t, err2)

	assert.Equal(t, result1, result2, "Same inputs should produce same reportData")
}

func TestCalculateReportDataMatchesSolidityABIEncode(t *testing.T) {
	// This test verifies the encoding matches Solidity's abi.encode(EnclaveInstanceData)
	// CRITICAL: This format must match the DKG contract's keccak256(abi.encode(enclaveInstanceData))

	round := uint32(1)
	validatorAddr := "0x1234567890123456789012345678901234567890"
	enclaveType := [32]byte{0xaa}
	enclaveCommKey := []byte{0xcc, 0xdd}
	dkgPubKey := []byte{0xaa, 0xbb}

	reportData, err := calculateReportData(round, validatorAddr, enclaveType, enclaveCommKey, dkgPubKey)
	require.NoError(t, err)

	// Manually compute using go-ethereum ABI to verify
	uint32Ty, _ := abi.NewType("uint32", "", nil)
	addressTy, _ := abi.NewType("address", "", nil)
	bytes32Ty, _ := abi.NewType("bytes32", "", nil)
	bytesTy, _ := abi.NewType("bytes", "", nil)

	args := abi.Arguments{
		{Type: uint32Ty},
		{Type: addressTy},
		{Type: bytes32Ty},
		{Type: bytesTy},
		{Type: bytesTy},
	}

	encoded, err := args.Pack(
		round,
		common.HexToAddress(validatorAddr),
		enclaveType,
		enclaveCommKey,
		dkgPubKey,
	)
	require.NoError(t, err)

	expectedHash := ecrypto.Keccak256(encoded)
	assert.Equal(t, expectedHash, reportData,
		"reportData must match keccak256(abi.encode(EnclaveInstanceData))")

	// Verify ABI encoding has expected structure:
	// 5 head slots (5*32=160) + 2 dynamic data sections
	assert.True(t, len(encoded) >= 160, "encoded data must have at least 5 head slots")
}

func TestCalculateReportDataInputVariation(t *testing.T) {
	baseRound := uint32(1)
	baseAddr := "0x1234567890123456789012345678901234567890"
	baseEnclaveType := [32]byte{0x01}
	baseCommKey := []byte{0xbb}
	baseDkgPub := []byte{0xaa}

	baseResult, err := calculateReportData(baseRound, baseAddr, baseEnclaveType, baseCommKey, baseDkgPub)
	require.NoError(t, err)

	// Change round
	result1, _ := calculateReportData(999, baseAddr, baseEnclaveType, baseCommKey, baseDkgPub)
	assert.NotEqual(t, baseResult, result1, "changing round should change reportData")

	// Change validator address
	result2, _ := calculateReportData(baseRound, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", baseEnclaveType, baseCommKey, baseDkgPub)
	assert.NotEqual(t, baseResult, result2, "changing validator address should change reportData")

	// Change enclave type
	result3, _ := calculateReportData(baseRound, baseAddr, [32]byte{0xff}, baseCommKey, baseDkgPub)
	assert.NotEqual(t, baseResult, result3, "changing enclaveType should change reportData")

	// Change enclaveCommKey
	result4, _ := calculateReportData(baseRound, baseAddr, baseEnclaveType, []byte{0xff}, baseDkgPub)
	assert.NotEqual(t, baseResult, result4, "changing enclaveCommKey should change reportData")

	// Change dkgPubKey
	result5, _ := calculateReportData(baseRound, baseAddr, baseEnclaveType, baseCommKey, []byte{0xff})
	assert.NotEqual(t, baseResult, result5, "changing dkgPubKey should change reportData")
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
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "positive large",
			input:    1000,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8},
		},
		{
			name:     "max int64",
			input:    9223372036854775807,
			expected: []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:     "negative",
			input:    -1,
			expected: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := int64ToBytes(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.Len(t, result, 8)
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
			expected: []byte{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "max uint32",
			input:    4294967295,
			expected: []byte{0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uint32ToBytes(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.Len(t, result, 4)
		})
	}
}

func TestEncodingFunctionsRoundTrip(t *testing.T) {
	t.Run("int64 round trip", func(t *testing.T) {
		testValues := []int64{0, 1, -1, 1000, -1000, 9223372036854775807, -9223372036854775808}
		for _, val := range testValues {
			encoded := int64ToBytes(val)
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
			var decoded uint32
			for i := 0; i < 4; i++ {
				decoded = (decoded << 8) | uint32(encoded[i])
			}
			assert.Equal(t, val, decoded, "uint32 should round-trip correctly")
		}
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

// Suppress unused import warnings
var _ = hex.EncodeToString

func BenchmarkCalculateReportData(b *testing.B) {
	round := uint32(1)
	validatorAddr := "0x1234567890123456789012345678901234567890"
	enclaveType := [32]byte{0x01}
	enclaveCommKey := make([]byte, 64)
	dkgPubKey := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = calculateReportData(round, validatorAddr, enclaveType, enclaveCommKey, dkgPubKey)
	}
}
