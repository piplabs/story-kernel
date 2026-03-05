package service

import (
	"testing"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCodeCommitmentResponse_FieldAccess(t *testing.T) {
	t.Run("response with code commitment", func(t *testing.T) {
		commitment := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		resp := &pb.GetCodeCommitmentResponse{
			CodeCommitment: commitment,
		}

		assert.Equal(t, commitment, resp.GetCodeCommitment())
	})

	t.Run("response with empty code commitment", func(t *testing.T) {
		resp := &pb.GetCodeCommitmentResponse{
			CodeCommitment: []byte{},
		}

		assert.Empty(t, resp.GetCodeCommitment())
	})

	t.Run("response with nil code commitment", func(t *testing.T) {
		resp := &pb.GetCodeCommitmentResponse{}

		assert.Nil(t, resp.GetCodeCommitment())
	})

	t.Run("response with 32-byte MRENCLAVE", func(t *testing.T) {
		// MRENCLAVE is always 32 bytes in SGX
		commitment := make([]byte, 32)
		for i := range 32 {
			commitment[i] = byte(i)
		}

		resp := &pb.GetCodeCommitmentResponse{
			CodeCommitment: commitment,
		}

		assert.Len(t, resp.GetCodeCommitment(), 32)
		assert.Equal(t, commitment, resp.GetCodeCommitment())
	})
}

func TestGetCodeCommitmentRequest_Empty(t *testing.T) {
	req := &pb.GetCodeCommitmentRequest{}
	require.NotNil(t, req)
}

func TestGetCodeCommitment_ImplementsInterface(t *testing.T) {
	// Verify that DKGServer satisfies the KernelServer interface
	// by checking that the GetCodeCommitment method has the correct signature.
	// This is a compile-time check enforced by the type assertion below.
	var _ pb.KernelServiceServer = (*DKGServer)(nil)
}
