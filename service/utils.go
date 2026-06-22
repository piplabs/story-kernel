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
// It produces keccak256(abi.encode(EnclaveInstanceData)) matching the Solidity struct:
//
//	struct EnclaveInstanceData {
//	    uint32 round;
//	    address validatorAddr;
//	    bytes32 enclaveType;
//	    bytes enclaveCommKey;
//	    bytes dkgPubKey;
//	}
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
