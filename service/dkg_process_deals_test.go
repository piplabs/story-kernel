package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func TestValidateProcessDealsRequest_MissingRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          0,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "round should be greater than 0")
}

func TestValidateProcessDealsRequest_MissingCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: nil,
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code commitment is required but missing")
}

func TestValidateProcessDealsRequest_EmptyDeals(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          nil,
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty deals to process")
}

func TestValidateProcessDealsRequest_Valid(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.NoError(t, err)
}

func TestValidateProcessDealsRequest_TableDriven(t *testing.T) {
	t.Parallel()

	validCC := []byte("32-byte-code-commitment-padding!!")
	validDeals := []*pb.Deal{{Index: 1}}

	tests := []struct {
		name           string
		round          uint32
		codeCommitment []byte
		deals          []*pb.Deal
		wantErr        bool
		errContains    string
	}{
		{
			name:           "all fields valid",
			round:          1,
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        false,
		},
		{
			name:           "round is zero",
			round:          0,
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        true,
			errContains:    "round should be greater than 0",
		},
		{
			name:           "code commitment is nil",
			round:          1,
			codeCommitment: nil,
			deals:          validDeals,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "code commitment is empty",
			round:          1,
			codeCommitment: []byte{},
			deals:          validDeals,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "deals is nil",
			round:          1,
			codeCommitment: validCC,
			deals:          nil,
			wantErr:        true,
			errContains:    "empty deals to process",
		},
		{
			name:           "deals is empty slice",
			round:          1,
			codeCommitment: validCC,
			deals:          []*pb.Deal{},
			wantErr:        true,
			errContains:    "empty deals to process",
		},
		{
			name:           "max round value",
			round:          ^uint32(0),
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &pb.ProcessDealsRequest{
				Round:          tc.round,
				CodeCommitment: tc.codeCommitment,
				Deals:          tc.deals,
			}

			err := validateProcessDealsRequest(req)
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
