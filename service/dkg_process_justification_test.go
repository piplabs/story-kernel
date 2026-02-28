package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// validJustificationProto returns a minimal but structurally valid
// pb.Justification for use in validation tests. The content is not
// cryptographically meaningful; it is only used to test request validation.
func validJustificationProto() *pb.Justification {
	return &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session-id"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("plain-deal-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: []byte("scalar-bytes-placeholder")},
				},
				Threshold:   2,
				Commitments: []*pb.Point{{Data: []byte("point-bytes")}},
			},
			Signature: []byte("signature"),
		},
	}
}

// TestValidateProcessJustificationRequest_MissingRound verifies that a request
// with round=0 fails validation with an appropriate error.
func TestValidateProcessJustificationRequest_MissingRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          0, // invalid: must be > 0
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: []*pb.Justification{validJustificationProto()},
	}

	err := validateProcessJustificationRequest(req)
	require.Error(t, err, "round=0 should fail validation")
	require.Contains(t, err.Error(), "round should be greater than 0")
}

// TestValidateProcessJustificationRequest_MissingCodeCommitment verifies that
// a request with an empty code commitment fails validation.
func TestValidateProcessJustificationRequest_MissingCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          1,
		CodeCommitment: nil, // missing
		Justifications: []*pb.Justification{validJustificationProto()},
	}

	err := validateProcessJustificationRequest(req)
	require.Error(t, err, "missing code commitment should fail validation")
	require.Contains(t, err.Error(), "code commitment is required but missing")
}

// TestValidateProcessJustificationRequest_MissingJustifications verifies that
// a request with empty justifications fails validation.
func TestValidateProcessJustificationRequest_MissingJustifications(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: nil, // missing
	}

	err := validateProcessJustificationRequest(req)
	require.Error(t, err, "missing justifications should fail validation")
	require.Contains(t, err.Error(), "justifications are required but missing")
}

// TestValidateProcessJustificationRequest_ValidRequest verifies that a request
// with all required fields passes validation.
func TestValidateProcessJustificationRequest_ValidRequest(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: []*pb.Justification{validJustificationProto()},
	}

	err := validateProcessJustificationRequest(req)
	require.NoError(t, err, "valid request should pass validation")
}

// TestValidateProcessJustificationRequest_EmptyCodeCommitment verifies that
// an empty (non-nil but zero-length) code commitment fails validation.
func TestValidateProcessJustificationRequest_EmptyCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          2,
		CodeCommitment: []byte{}, // empty slice
		Justifications: []*pb.Justification{validJustificationProto()},
	}

	err := validateProcessJustificationRequest(req)
	require.Error(t, err, "empty code commitment slice should fail validation")
	require.Contains(t, err.Error(), "code commitment is required but missing")
}

// TestValidateProcessJustificationRequest_MaxRound verifies that the maximum
// uint32 round value is accepted.
func TestValidateProcessJustificationRequest_MaxRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          ^uint32(0), // max uint32
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: []*pb.Justification{validJustificationProto()},
	}

	err := validateProcessJustificationRequest(req)
	require.NoError(t, err, "maximum round value should pass validation")
}

// TestValidateProcessJustificationRequest_MultipleJustifications verifies that
// a request with multiple justifications passes validation.
func TestValidateProcessJustificationRequest_MultipleJustifications(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: []*pb.Justification{
			validJustificationProto(),
			validJustificationProto(),
			validJustificationProto(),
		},
	}

	err := validateProcessJustificationRequest(req)
	require.NoError(t, err, "multiple justifications should pass validation")
}

// TestValidateProcessJustificationRequest_EmptyJustificationsSlice verifies that
// a request with an empty (non-nil) justifications slice fails validation.
func TestValidateProcessJustificationRequest_EmptyJustificationsSlice(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessJustificationRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Justifications: []*pb.Justification{}, // empty slice
	}

	err := validateProcessJustificationRequest(req)
	require.Error(t, err, "empty justifications slice should fail validation")
	require.Contains(t, err.Error(), "justifications are required but missing")
}

// TestValidateProcessJustificationRequest_TableDriven exercises all validation
// branches via a table-driven approach for completeness.
func TestValidateProcessJustificationRequest_TableDriven(t *testing.T) {
	t.Parallel()

	validCC := []byte("32-byte-code-commitment-padding!!")
	validJs := []*pb.Justification{validJustificationProto()}

	tests := []struct {
		name           string
		round          uint32
		codeCommitment []byte
		justifications []*pb.Justification
		wantErr        bool
		errContains    string
	}{
		{
			name:           "all fields valid",
			round:          1,
			codeCommitment: validCC,
			justifications: validJs,
			wantErr:        false,
		},
		{
			name:           "round is zero",
			round:          0,
			codeCommitment: validCC,
			justifications: validJs,
			wantErr:        true,
			errContains:    "round should be greater than 0",
		},
		{
			name:           "code commitment is nil",
			round:          1,
			codeCommitment: nil,
			justifications: validJs,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "code commitment is empty",
			round:          1,
			codeCommitment: []byte{},
			justifications: validJs,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "justifications is nil",
			round:          1,
			codeCommitment: validCC,
			justifications: nil,
			wantErr:        true,
			errContains:    "justifications are required but missing",
		},
		{
			name:           "justifications is empty slice",
			round:          1,
			codeCommitment: validCC,
			justifications: []*pb.Justification{},
			wantErr:        true,
			errContains:    "justifications are required but missing",
		},
		{
			name:           "round and code commitment both missing",
			round:          0,
			codeCommitment: nil,
			justifications: validJs,
			wantErr:        true,
			// The first error encountered should be about round
			errContains: "round should be greater than 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &pb.ProcessJustificationRequest{
				Round:          tc.round,
				CodeCommitment: tc.codeCommitment,
				Justifications: tc.justifications,
			}

			err := validateProcessJustificationRequest(req)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
