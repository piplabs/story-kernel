package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func TestValidateProcessResponsesRequest_MissingRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          0,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "round should be greater than 0")
}

func TestValidateProcessResponsesRequest_MissingCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: nil,
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code commitment is required but missing")
}

func TestValidateProcessResponsesRequest_EmptyResponses(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      nil,
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty responses to process")
}

func TestValidateProcessResponsesRequest_Valid(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.NoError(t, err)
}

func TestValidateProcessResponsesRequest_TableDriven(t *testing.T) {
	t.Parallel()

	validCC := []byte("32-byte-code-commitment-padding!!")
	validResps := []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}}

	tests := []struct {
		name           string
		round          uint32
		codeCommitment []byte
		responses      []*pb.Response
		wantErr        bool
		errContains    string
	}{
		{
			name:           "all fields valid",
			round:          1,
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        false,
		},
		{
			name:           "round is zero",
			round:          0,
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        true,
			errContains:    "round should be greater than 0",
		},
		{
			name:           "code commitment is nil",
			round:          1,
			codeCommitment: nil,
			responses:      validResps,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "code commitment is empty",
			round:          1,
			codeCommitment: []byte{},
			responses:      validResps,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "responses is nil",
			round:          1,
			codeCommitment: validCC,
			responses:      nil,
			wantErr:        true,
			errContains:    "empty responses to process",
		},
		{
			name:           "responses is empty slice",
			round:          1,
			codeCommitment: validCC,
			responses:      []*pb.Response{},
			wantErr:        true,
			errContains:    "empty responses to process",
		},
		{
			name:           "max round value",
			round:          ^uint32(0),
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &pb.ProcessResponsesRequest{
				Round:          tc.round,
				CodeCommitment: tc.codeCommitment,
				Responses:      tc.responses,
			}

			err := validateProcessResponsesRequest(req)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
