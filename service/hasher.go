package service

import (
	"fmt"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// finalizationSignatureMaterial holds the fields committed to by the validator
// signature on a DKG finalization response. RLP encoding gives each field an
// unambiguous length prefix, preventing boundary-shift collisions that arise
// from raw concatenation of variable-length byte slices.
type finalizationSignatureMaterial struct {
	CodeCommitment   []byte
	Round            uint32
	ParticipantsRoot [32]byte
	GlobalPubKey     []byte
	PublicCoeffs     [][]byte
	PubKeyShare      []byte
}

// hashFinalizeDKGResponse hashes the final response payload to sign using RLP encoding.
//
// SGX and the supported TDX direct path both produce a 32-byte code commitment
// (MRENCLAVE for SGX, keccak256(RTMR2) for TDX) — see backend.computeSelfIdentity.
// `codeCommitment` is required to be that 32-byte hybrid-hook value; anything
// else is a backend-contract violation and fails fast here.
func hashFinalizeDKGResponse(codeCommitment []byte, round uint32, participantsRoot [32]byte, globalPubKey []byte, publicCoeffsBz [][]byte, pubKeyShare []byte) ([]byte, error) {
	if len(codeCommitment) != 32 {
		return nil, fmt.Errorf("code commitment must be 32 bytes, got %d", len(codeCommitment))
	}

	for i, coeff := range publicCoeffsBz {
		if len(coeff) == 0 {
			return nil, fmt.Errorf("public coefficient at index %d is empty", i)
		}
	}

	material := finalizationSignatureMaterial{
		CodeCommitment:   codeCommitment,
		Round:            round,
		ParticipantsRoot: participantsRoot,
		GlobalPubKey:     globalPubKey,
		PublicCoeffs:     publicCoeffsBz,
		PubKeyShare:      pubKeyShare,
	}
	encoded, err := rlp.EncodeToBytes(material)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode finalization signature material: %w", err)
	}

	return ecrypto.Keccak256(encoded), nil
}
