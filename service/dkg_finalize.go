package service

import (
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func validateFinalizeDKGRequest(req *pb.FinalizeDKGRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	return nil
}

// This matches the validation logic in the Story blockchain DKG module.
func calculateParticipantsRoot(registrations []*pb.DKGRegistration) ([32]byte, error) {
	if len(registrations) == 0 {
		return [32]byte{}, errors.New("no registrations provided")
	}

	// Extract and validate addresses
	addrs := make([]string, 0, len(registrations))
	for _, reg := range registrations {
		addr := strings.ToLower(strings.TrimSpace(reg.GetValidatorAddr()))
		if !common.IsHexAddress(addr) {
			return [32]byte{}, errors.Errorf("invalid validator evm address: %s", reg.GetValidatorAddr())
		}
		addrs = append(addrs, addr)
	}

	// Sort addresses
	slices.Sort(addrs)

	// Concatenate address bytes
	buf := make([]byte, 0, common.AddressLength*len(addrs))
	for _, a := range addrs {
		evmAddr := common.HexToAddress(a)
		buf = append(buf, evmAddr.Bytes()...)
	}

	// Calculate Keccak256 hash
	hash := ecrypto.Keccak256Hash(buf)

	return hash, nil
}
