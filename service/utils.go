package service

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	ethereumAddressSize = 20
	uint32Size          = 4
	uint64Size          = 8
	blockHashSize       = 32
	// dkgPubKey and enclaveCommKey are the trailing dynamic fields of the packed
	// preimage. Their lengths must be pinned so the concatenation stays injective
	// (adjacent variable-length fields are otherwise ambiguous). dkgPubKey is the
	// ed25519 public key (32 bytes); enclaveCommKey is the secp256k1 public key
	// with the uncompressed-form prefix stripped (64 bytes). These match the
	// require()s in DKG.sol::register.
	dkgPubKeySize      = 32
	enclaveCommKeySize = 64
)

// calculateReportData computes the TEE attestation report data for DKG registration.
// It produces keccak256 over the tightly packed (abi.encodePacked, no ABI
// offset/length words) concatenation of, in order:
//
//	validatorAddr(20) || round(4, big-endian) || startBlockHeight(8, big-endian)
//	  || startBlockHash(32) || dkgPubKey(32) || enclaveCommKey(64)
//
// The two trailing dynamic fields are length-pinned (see dkgPubKeySize /
// enclaveCommKeySize) so the packed preimage is injective. This must match the
// on-chain DKG.register report-data reconstruction byte-for-byte; a golden
// vector shared with DKG.sol guards against drift.
func calculateReportData(validatorAddr string, round uint32, startBlockHeight uint64, startBlockHash []byte, dkgPubKey, enclaveCommKey []byte) ([]byte, error) {
	addr := strings.TrimPrefix(validatorAddr, "0x")

	addrBytes, err := hex.DecodeString(addr)
	if err != nil || len(addrBytes) != ethereumAddressSize {
		return nil, fmt.Errorf("invalid address (%s): %w", addr, err)
	}

	if len(startBlockHash) != blockHashSize {
		return nil, fmt.Errorf("startBlockHash must be %d bytes, got %d", blockHashSize, len(startBlockHash))
	}

	if len(dkgPubKey) != dkgPubKeySize {
		return nil, fmt.Errorf("dkgPubKey must be %d bytes, got %d", dkgPubKeySize, len(dkgPubKey))
	}

	if len(enclaveCommKey) != enclaveCommKeySize {
		return nil, fmt.Errorf("enclaveCommKey must be %d bytes, got %d", enclaveCommKeySize, len(enclaveCommKey))
	}

	// Pre-allocate buffer for: validatorAddr(20) + round(4) + startBlockHeight(8) + startBlockHash(32) + dkgPubKey(32) + enclaveCommKey(64)
	encoded := make([]byte, 0, ethereumAddressSize+uint32Size+uint64Size+blockHashSize+dkgPubKeySize+enclaveCommKeySize)
	encoded = append(encoded, addrBytes...)
	encoded = append(encoded, uint32ToBytes(round)...)
	encoded = append(encoded, int64ToBytes(int64(startBlockHeight))...)
	encoded = append(encoded, startBlockHash...)
	encoded = append(encoded, dkgPubKey...)
	encoded = append(encoded, enclaveCommKey...)

	return ecrypto.Keccak256(encoded), nil
}

// int64ToBytes converts an int64 to an 8-byte big-endian representation.
// This matches Solidity's abi.encodePacked behavior for uint64.
func int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func toUint256Bytes(v uint32) []byte {
	out := make([]byte, 32)
	binary.BigEndian.PutUint32(out[28:], v)

	return out
}

// uint32ToBytes converts a uint32 to a 4-byte big-endian representation.
// This matches Solidity's abi.encodePacked behavior for uint32.
func uint32ToBytes(i uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

// reverseBytes returns a new slice with bytes reversed.
func reverseBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}

	return out
}

// lazy memoizes a value produced by load, running it at most once on the first
// Get. It lets a request defer an expensive load (e.g. reading DKG state from
// disk) so the normal path pays nothing, while a retry loads it exactly once and
// reuses it for every subsequent item in the same call. Not safe for concurrent
// use — intended for a single request goroutine.
type lazy[T any] struct {
	load   func() (T, error)
	value  T
	loaded bool
	err    error
}

func (l *lazy[T]) Get() (T, error) {
	if !l.loaded {
		l.value, l.err = l.load()
		l.loaded = true
	}

	return l.value, l.err
}
