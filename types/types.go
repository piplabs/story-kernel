package types

import (
	"fmt"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

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
		Index: j.Index,
		VssJustification: &pb.VSSJustification{
			SessionId: j.Justification.SessionID,
			Index:     j.Justification.Index,
			PlainDeal: &pb.PlainDeal{
				SessionId: j.Justification.Deal.SessionID,
				SecShare: &pb.SecShare{
					I: uint32(j.Justification.Deal.SecShare.I),
					V: &pb.Scalar{Data: secSharescalar},
				},
				Threshold:   j.Justification.Deal.T,
				Commitments: commitments,
			},
			Signature: j.Justification.Signature,
		},
	}, nil
}
