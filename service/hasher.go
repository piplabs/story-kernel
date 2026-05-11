package service

import (
	"fmt"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pkg/errors"
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
// TDX backends produce a 240-byte raw commitment (MRTD || RTMR0..3); SGX produces
// 32-byte MRENCLAVE. The on-chain contract stores the keccak256-compressed 32-byte
// form in DKGRegistration storage and emits it on the Finalized event, which is what
// verifyFinalizationSignature on the CL side uses. Compress here so both sides sign
// over the same 32-byte value regardless of backend.
func hashFinalizeDKGResponse(codeCommitment []byte, round uint32, participantsRoot [32]byte, globalPubKey []byte, publicCoeffsBz [][]byte, pubKeyShare []byte) ([]byte, error) {
	if len(codeCommitment) == 0 {
		return nil, errors.New("code commitment is empty")
	}
	if len(codeCommitment) != 32 {
		codeCommitment = ecrypto.Keccak256(codeCommitment)
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
