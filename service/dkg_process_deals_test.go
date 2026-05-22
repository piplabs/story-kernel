package service

import (
	"errors"
	"fmt"
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

// TestIsAlreadyProcessedErr pins the kyber v4.0.0-pre2 idempotent-error
// strings exactly so that a kyber upgrade renaming any of them fails this
// test loudly. See the NOTE on isAlreadyProcessedErr for upgrade procedure.
func TestIsAlreadyProcessedErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"verifier-already-deal", errDealAlreadyProcessedVerbatim(), true},
		{"already-existing-response", errAlreadyExistingResponseVerbatim(), true},
		{"justification-on-approval", errJustificationOnApprovalVerbatim(), true},
		{"case-insensitive", errors.New("VSS: ALREADY EXISTING RESPONSE FROM SAME ORIGIN"), true},
		{"wrapped-once", errWrap(errDealAlreadyProcessedVerbatim()), true},
		{"unrelated-error", errors.New("dkg: dist deal out of bounds index"), false},
		{"nil", nil, false},
		{"plain-non-match", errors.New("network unreachable"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, isAlreadyProcessedErr(tc.err))
		})
	}
}

// The next three helpers reproduce the EXACT kyber v4.0.0-pre2 error strings
// (lifted from share/vss/pedersen/vss.go lines 552, 656, 639). If a kyber
// upgrade changes the wording, the corresponding TestIsAlreadyProcessedErr
// case fails and points at the substring that needs updating.
func errDealAlreadyProcessedVerbatim() error {
	return errors.New("vss: verifier already received a deal")
}

func errAlreadyExistingResponseVerbatim() error {
	return errors.New("vss: already existing response from same origin")
}

func errJustificationOnApprovalVerbatim() error {
	return errors.New("vss: justification received for an approval")
}

// errWrap returns an error that wraps the input — used to verify
// isAlreadyProcessedErr handles wrapped errors via fmt.Errorf "%w".
func errWrap(inner error) error {
	return fmt.Errorf("kernel: %w", inner)
}
