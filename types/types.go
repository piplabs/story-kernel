package types

import (
	"fmt"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

func ConvertToDeal(deal *pb.Deal) *dkg.Deal {
	return &dkg.Deal{
		Index: deal.GetIndex(),
		Deal: &vss.EncryptedDeal{
			DHKey:     deal.GetDeal().GetDhKey(),
			Signature: deal.GetDeal().GetSignature(),
			Nonce:     deal.GetDeal().GetNonce(),
			Cipher:    deal.GetDeal().GetCipher(),
		},
		Signature: deal.GetSignature(),
	}
}

func ConvertToRespProto(resp *dkg.Response) *pb.Response {
	return &pb.Response{
		Index: resp.Index,
		VssResponse: &pb.VSSResponse{
			SessionId: resp.Response.SessionID,
			Index:     resp.Response.Index,
			Status:    resp.Response.Status,
			Signature: resp.Response.Signature,
		},
	}
}

func ConvertToVSSResp(response *pb.Response) *dkg.Response {
	return &dkg.Response{
		Index: response.GetIndex(),
		Response: &vss.Response{
			SessionID: response.GetVssResponse().GetSessionId(),
			Index:     response.GetVssResponse().GetIndex(),
			Status:    response.GetVssResponse().GetStatus(),
			Signature: response.GetVssResponse().GetSignature(),
		},
	}
}

// ConvertToJustification converts a protobuf Justification to the kyber Justification type
// used by DistKeyGenerator.ProcessJustification().
//
// Index convention (all 0-based, matching kyber internals):
//   - j.Index (dkg.Justification.Index): dealer index, 0-based
//   - vssJ.Index (vss.Justification.Index): verifier/recipient index, 0-based
//   - secShare.I (share.PriShare.I): secret share evaluation index, 0-based
//     kyber's PriPoly.Eval(i) returns PriShare{I: i, V: f(i+1)}, so I is 0-based
//     but the polynomial is evaluated at x = 1 + I internally.
func ConvertToJustification(j *pb.Justification) (*dkg.Justification, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	vssJ := j.GetVssJustification()
	if vssJ == nil {
		return nil, fmt.Errorf("justification has nil VSSJustification")
	}

	plainDeal := vssJ.GetPlainDeal()
	if plainDeal == nil {
		return nil, fmt.Errorf("justification has nil PlainDeal")
	}

	secShare := plainDeal.GetSecShare()
	if secShare == nil || secShare.GetV() == nil {
		return nil, fmt.Errorf("justification has nil SecShare or scalar value")
	}

	// Unmarshal the secret share scalar (0-based index preserved as-is from proto)
	shareScalar := suite.Scalar()
	if err := shareScalar.UnmarshalBinary(secShare.GetV().GetData()); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret share scalar: %w", err)
	}

	// Unmarshal commitments
	commitments := make([]kyber.Point, 0, len(plainDeal.GetCommitments()))
	for _, c := range plainDeal.GetCommitments() {
		point := suite.Point()
		if err := point.UnmarshalBinary(c.GetData()); err != nil {
			return nil, fmt.Errorf("failed to unmarshal commitment point: %w", err)
		}
		commitments = append(commitments, point)
	}

	return &dkg.Justification{
		Index: j.GetIndex(), // 0-based dealer index
		Justification: &vss.Justification{
			SessionID: vssJ.GetSessionId(),
			Index:     vssJ.GetIndex(), // 0-based verifier/recipient index
			Deal: &vss.Deal{
				SessionID: plainDeal.GetSessionId(),
				SecShare: &share.PriShare{
					I: int(secShare.GetI()), // 0-based, matches kyber's PriPoly.Eval(i) output
					V: shareScalar,
				},
				T:           plainDeal.GetThreshold(),
				Commitments: commitments,
			},
			Signature: vssJ.GetSignature(),
		},
	}, nil
}

// ConvertToJustificationProto converts a kyber Justification back to protobuf format.
// All indices are preserved as 0-based (matching kyber's internal convention).
func ConvertToJustificationProto(j *dkg.Justification) (*pb.Justification, error) {
	secSharescalar, err := j.Justification.Deal.SecShare.V.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the secret share: %w", err)
	}

	var commitments []*pb.Point
	for _, comm := range j.Justification.Deal.Commitments {
		c, err := comm.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal the commitments: %w", err)
		}

		commitments = append(commitments, &pb.Point{Data: c})
	}

	return &pb.Justification{
		Index: j.Index, // 0-based dealer index
		VssJustification: &pb.VSSJustification{
			SessionId: j.Justification.SessionID,
			Index:     j.Justification.Index, // 0-based verifier/recipient index
			PlainDeal: &pb.PlainDeal{
				SessionId: j.Justification.Deal.SessionID,
				SecShare: &pb.SecShare{
					I: uint32(j.Justification.Deal.SecShare.I), // 0-based, matches kyber convention
					V: &pb.Scalar{Data: secSharescalar},
				},
				Threshold:   j.Justification.Deal.T,
				Commitments: commitments,
			},
			Signature: j.Justification.Signature,
		},
	}, nil
}
