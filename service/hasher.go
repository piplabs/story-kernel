package service

import (
	"fmt"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// hashFinalizeDKGResponse hashes the final response payload to sign.
func hashFinalizeDKGResponse(codeCommitment []byte, round uint32, participantsRoot [32]byte, globalPubKey []byte, publicCoeffsBz [][]byte, pubKeyShare []byte) ([]byte, error) {
	if len(codeCommitment) != 32 {
		return nil, errors.New("the length of code commitment should be 32")
	}

	// concat
	encoded := append([]byte{}, codeCommitment[:]...)
	encoded = append(encoded, uint32ToBytes(round)...)
	encoded = append(encoded, participantsRoot[:]...)
	encoded = append(encoded, globalPubKey...)

	for i, coeff := range publicCoeffsBz {
		if len(coeff) == 0 {
			return nil, fmt.Errorf("public coefficient at index %d is empty", i)
		}
		encoded = append(encoded, coeff...)
	}

	encoded = append(encoded, pubKeyShare...)

	hash := ecrypto.Keccak256(encoded)

	return toEthSignedMessageHash(hash), nil
}
