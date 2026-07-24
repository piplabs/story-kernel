package service

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validDkgPubKey / validEnclaveCommKey return correctly-sized stand-in keys.
// calculateReportData pins dkgPubKey to 32 bytes and enclaveCommKey to 64
// bytes so the packed preimage stays injective; tests must therefore feed
// real-length keys. The first byte is varied via the `seed` argument so a
// caller can produce two distinct-but-valid keys.
func validDkgPubKey(seed byte) []byte {
	k := make([]byte, dkgPubKeySize)
	for i := range k {
		k[i] = byte(i)
	}
	k[0] = seed
	return k
}

func validEnclaveCommKey(seed byte) []byte {
	k := make([]byte, enclaveCommKeySize)
	for i := range k {
		k[i] = byte(i)
	}
	k[0] = seed
	return k
}

func TestCalculateReportData(t *testing.T) {
	validStartBlockHash := make([]byte, 32)
	validStartBlockHash[0] = 0xab

	tests := []struct {
		name             string
		validatorAddr    string
		round            uint32
		startBlockHeight uint64
		startBlockHash   []byte
		dkgPubKey        []byte
		enclaveCommKey   []byte
		wantErr          bool
		errContains      string
	}{
		{
			name:             "valid input",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   validEnclaveCommKey(0x05),
			wantErr:          false,
		},
		{
			name:             "valid input without 0x prefix",
			validatorAddr:    "1234567890123456789012345678901234567890",
			round:            100,
			startBlockHeight: 200,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0xaa),
			enclaveCommKey:   validEnclaveCommKey(0xbb),
			wantErr:          false,
		},
		{
			name:             "invalid address - too short",
			validatorAddr:    "0x1234",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   validEnclaveCommKey(0x02),
			wantErr:          true,
			errContains:      "invalid address",
		},
		{
			name:             "invalid address - not hex",
			validatorAddr:    "0xZZZZ567890123456789012345678901234567890",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   validEnclaveCommKey(0x02),
			wantErr:          true,
			errContains:      "invalid address",
		},
		{
			name:             "invalid startBlockHash - too short",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   []byte{0x01, 0x02},
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   validEnclaveCommKey(0x02),
			wantErr:          true,
			errContains:      "startBlockHash must be 32 bytes",
		},
		{
			name:             "invalid dkgPubKey - too short",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        []byte{0x01, 0x02, 0x03},
			enclaveCommKey:   validEnclaveCommKey(0x05),
			wantErr:          true,
			errContains:      "dkgPubKey must be 32 bytes",
		},
		{
			name:             "invalid enclaveCommKey - too long",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            1,
			startBlockHeight: 100,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   make([]byte, 66),
			wantErr:          true,
			errContains:      "enclaveCommKey must be 64 bytes",
		},
		{
			name:             "large round number",
			validatorAddr:    "0x1234567890123456789012345678901234567890",
			round:            4294967295,
			startBlockHeight: 1000000,
			startBlockHash:   validStartBlockHash,
			dkgPubKey:        validDkgPubKey(0x01),
			enclaveCommKey:   validEnclaveCommKey(0x02),
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calculateReportData(
				tt.validatorAddr,
				tt.round,
				tt.startBlockHeight,
				tt.startBlockHash,
				tt.dkgPubKey,
				tt.enclaveCommKey,
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
	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(42)
	startBlockHeight := uint64(1000)
	startBlockHash := make([]byte, 32)
	startBlockHash[0] = 0xab
	dkgPubKey := validDkgPubKey(0xaa)
	enclaveCommKey := validEnclaveCommKey(0xdd)

	result1, err1 := calculateReportData(validatorAddr, round, startBlockHeight, startBlockHash, dkgPubKey, enclaveCommKey)
	require.NoError(t, err1)

	result2, err2 := calculateReportData(validatorAddr, round, startBlockHeight, startBlockHash, dkgPubKey, enclaveCommKey)
	require.NoError(t, err2)

	assert.Equal(t, result1, result2, "Same inputs should produce same reportData")
}

func TestCalculateReportDataMatchesSolidityABIEncodePacked(t *testing.T) {
	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(1)
	startBlockHeight := uint64(1000)
	startBlockHash := make([]byte, 32)
	startBlockHash[0] = 0xab
	dkgPubKey := validDkgPubKey(0xaa)
	enclaveCommKey := validEnclaveCommKey(0xcc)

	reportData, err := calculateReportData(validatorAddr, round, startBlockHeight, startBlockHash, dkgPubKey, enclaveCommKey)
	require.NoError(t, err)

	addrBytes := common.HexToAddress(validatorAddr).Bytes()
	roundBytes := uint32ToBytes(round)
	heightBytes := int64ToBytes(int64(startBlockHeight))

	expected := make([]byte, 0)
	expected = append(expected, addrBytes...)
	expected = append(expected, roundBytes...)
	expected = append(expected, heightBytes...)
	expected = append(expected, startBlockHash...)
	expected = append(expected, dkgPubKey...)
	expected = append(expected, enclaveCommKey...)

	expectedHash := ecrypto.Keccak256(expected)
	assert.Equal(t, expectedHash, reportData,
		"reportData must match keccak256(abi.encodePacked(validatorAddr, round, startBlockHeight, startBlockHash, dkgPubKey, enclaveCommKey))")

	assert.Equal(t, 20+4+8+32+len(dkgPubKey)+len(enclaveCommKey), len(expected),
		"encodePacked should concatenate without padding")
}

func TestCalculateReportDataInputVariation(t *testing.T) {
	baseAddr := "0x1234567890123456789012345678901234567890"
	baseRound := uint32(1)
	baseHeight := uint64(1000)
	baseHash := make([]byte, 32)
	baseHash[0] = 0x01
	baseDkgPub := validDkgPubKey(0xaa)
	baseCommKey := validEnclaveCommKey(0xbb)

	baseResult, err := calculateReportData(baseAddr, baseRound, baseHeight, baseHash, baseDkgPub, baseCommKey)
	require.NoError(t, err)

	result1, _ := calculateReportData("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", baseRound, baseHeight, baseHash, baseDkgPub, baseCommKey)
	assert.NotEqual(t, baseResult, result1, "changing validator address should change reportData")

	result2, _ := calculateReportData(baseAddr, 999, baseHeight, baseHash, baseDkgPub, baseCommKey)
	assert.NotEqual(t, baseResult, result2, "changing round should change reportData")

	result3, _ := calculateReportData(baseAddr, baseRound, 9999, baseHash, baseDkgPub, baseCommKey)
	assert.NotEqual(t, baseResult, result3, "changing startBlockHeight should change reportData")

	altHash := make([]byte, 32)
	altHash[0] = 0xff
	result4, _ := calculateReportData(baseAddr, baseRound, baseHeight, altHash, baseDkgPub, baseCommKey)
	assert.NotEqual(t, baseResult, result4, "changing startBlockHash should change reportData")

	result5, _ := calculateReportData(baseAddr, baseRound, baseHeight, baseHash, validDkgPubKey(0xff), baseCommKey)
	assert.NotEqual(t, baseResult, result5, "changing dkgPubKey should change reportData")

	result6, _ := calculateReportData(baseAddr, baseRound, baseHeight, baseHash, baseDkgPub, validEnclaveCommKey(0xff))
	assert.NotEqual(t, baseResult, result6, "changing enclaveCommKey should change reportData")
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
	validatorAddr := "0x1234567890123456789012345678901234567890"
	round := uint32(1)
	startBlockHeight := uint64(1000)
	startBlockHash := make([]byte, 32)
	dkgPubKey := make([]byte, 32)
	enclaveCommKey := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = calculateReportData(validatorAddr, round, startBlockHeight, startBlockHash, dkgPubKey, enclaveCommKey)
	}
}
