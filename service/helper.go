package service

import (
	"sort"

	"github.com/pkg/errors"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

func extractSortedPubKeys(suite *edwards25519.SuiteEd25519, regs []*pb.DKGRegistration) ([]kyber.Point, error) {
	if len(regs) == 0 {
		return nil, nil
	}

	sort.SliceStable(regs, func(i, j int) bool {
		return regs[i].GetIndex() < regs[j].GetIndex()
	})

	pubs := make([]kyber.Point, 0, len(regs))
	for _, reg := range regs {
		point := suite.Point()
		if err := point.UnmarshalBinary(reg.GetDkgPubKey()); err != nil {
			return nil, errors.Wrap(err, "invalid public key")
		}
		pubs = append(pubs, point)
	}

	return pubs, nil
}

func isInActiveValSet(activeValSet []string, validator string) bool {
	for _, v := range activeValSet {
		if v == validator {
			return true
		}
	}

	return false
}

func createGenerateDealsResponse(round uint32, codeCommitment []byte, deals map[int]*dkg.Deal) *pb.GenerateDealsResponse {
	resp := &pb.GenerateDealsResponse{
		Round:          round,
		CodeCommitment: codeCommitment,
	}

	for i, deal := range deals {
		pbDeal := &pb.Deal{
			Index:          deal.Index,
			RecipientIndex: uint32(i),
			Deal: &pb.EncryptedDeal{
				DhKey:     deal.Deal.DHKey,
				Signature: deal.Deal.Signature,
				Nonce:     deal.Deal.Nonce,
				Cipher:    deal.Deal.Cipher,
			},
			Signature: deal.Signature,
		}
		resp.Deals = append(resp.Deals, pbDeal)
	}

	return resp
}

// MarshalPoints converts a slice of kyber.Point into a slice of []byte.
// Each point is marshaled using its MarshalBinary() method.
func MarshalPoints(points []kyber.Point) ([][]byte, error) {
	out := make([][]byte, 0, len(points))

	for _, p := range points {
		bz, err := p.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal point")
		}
		out = append(out, bz)
	}

	return out, nil
}

func UnmarshalPoints(suite *edwards25519.SuiteEd25519, bzs [][]byte) ([]kyber.Point, error) {
	pts := make([]kyber.Point, 0, len(bzs))

	for i, bz := range bzs {
		p := suite.Point()
		if err := p.UnmarshalBinary(bz); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal point at index %d", i)
		}

		pts = append(pts, p)
	}

	return pts, nil
}
