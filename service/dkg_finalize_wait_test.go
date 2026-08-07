package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// filteredRegs is the post-invalidation participant set the chain agrees on (val1 removed):
// only the participants that remain VERIFIED/FINALIZED after missing-dealer invalidation.
func filteredRegs() []*pb.DKGRegistration {
	return []*pb.DKGRegistration{
		{Index: 1, Round: 42, ValidatorAddr: "0xC6cB20293dD838C3E839198B9F753c6Ed29e0c9B"}, // val2
		{Index: 3, Round: 42, ValidatorAddr: "0xc025E30e4ff0A68cB623Ac671933B6FE99eF7Cc7"}, // val4
	}
}

// TestWaitForFinalizationRegistrations_WaitsForStage verifies the kernel does not read the
// participant set while the light client still reports an earlier stage (which would include
// an invalidated dealer), and only reads it once the finalization stage is observed.
func TestWaitForFinalizationRegistrations_WaitsForStage(t *testing.T) {
	stub := &stubQueryClient{
		networks: []*pb.DKGNetwork{
			{Round: 42, Stage: pb.DKGStage_DKG_STAGE_DEALING},      // call 1: light client still lagging
			{Round: 42, Stage: pb.DKGStage_DKG_STAGE_FINALIZATION}, // call 2: caught up to finalization block
		},
		registrations: [][]*pb.DKGRegistration{filteredRegs()},
	}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(t.Context(), "cc", 42)
	require.NoError(t, err)
	require.Equal(t, filteredRegs(), regs)
	require.Equal(t, int32(2), stub.netCalls.Load(), "polls stage until finalization (1 lag + 1 caught up)")
	require.Equal(t, int32(1), stub.regCalls.Load(), "registrations read exactly once, after the stage is reached")
}

// TestWaitForFinalizationRegistrations_Immediate verifies no wait happens when the light
// client has already observed the finalization stage.
func TestWaitForFinalizationRegistrations_Immediate(t *testing.T) {
	stub := &stubQueryClient{
		networks:      []*pb.DKGNetwork{{Round: 42, Stage: pb.DKGStage_DKG_STAGE_FINALIZATION}},
		registrations: [][]*pb.DKGRegistration{filteredRegs()},
	}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(t.Context(), "cc", 42)
	require.NoError(t, err)
	require.Equal(t, filteredRegs(), regs)
	require.Equal(t, int32(1), stub.netCalls.Load())
	require.Equal(t, int32(1), stub.regCalls.Load())
}

// TestWaitForFinalizationRegistrations_RetryExhausted verifies that if the finalization stage
// is never observed, the call fails with ErrLightClientLag and never reads a stale set.
func TestWaitForFinalizationRegistrations_RetryExhausted(t *testing.T) {
	stub := &stubQueryClient{
		networks:      []*pb.DKGNetwork{{Round: 42, Stage: pb.DKGStage_DKG_STAGE_DEALING}},
		registrations: [][]*pb.DKGRegistration{filteredRegs()},
	}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(t.Context(), "cc", 42)
	require.Error(t, err)
	require.Nil(t, regs)
	require.True(t, errors.Is(err, ErrLightClientLag), "exhaustion must preserve ErrLightClientLag")
	require.Equal(t, int32(finalizeStageRetryAttempts), stub.netCalls.Load())
	require.Equal(t, int32(0), stub.regCalls.Load(), "must never read the participant set while lagging")
}

// TestWaitForFinalizationRegistrations_NotFoundThenStage verifies a not-found read (light
// client has not observed the round at all) is retried like an earlier stage instead of
// failing the call.
func TestWaitForFinalizationRegistrations_NotFoundThenStage(t *testing.T) {
	stub := &stubQueryClient{
		netErrs:       []error{notFoundErr()}, // call 1: round not visible yet
		networks:      []*pb.DKGNetwork{{Round: 42, Stage: pb.DKGStage_DKG_STAGE_FINALIZATION}},
		registrations: [][]*pb.DKGRegistration{filteredRegs()},
	}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(t.Context(), "cc", 42)
	require.NoError(t, err)
	require.Equal(t, filteredRegs(), regs)
	require.Equal(t, int32(2), stub.netCalls.Load(), "polls through the not-found read (1 lag + 1 caught up)")
	require.Equal(t, int32(1), stub.regCalls.Load())
}

// TestWaitForFinalizationRegistrations_NetworkError verifies a network query error is returned
// directly without retrying.
func TestWaitForFinalizationRegistrations_NetworkError(t *testing.T) {
	wantErr := errors.New("rpc down")
	stub := &stubQueryClient{netErr: wantErr}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(t.Context(), "cc", 42)
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, regs)
	require.Equal(t, int32(1), stub.netCalls.Load(), "network error must not be retried")
}

// TestWaitForFinalizationRegistrations_ContextCanceled verifies a caller going away
// mid-wait stops the retry loop promptly instead of burning the remaining budget.
func TestWaitForFinalizationRegistrations_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	stub := &stubQueryClient{
		networks: []*pb.DKGNetwork{{Round: 42, Stage: pb.DKGStage_DKG_STAGE_DEALING}},
	}

	s := &DKGServer{QueryClient: stub}

	regs, err := s.waitForFinalizationRegistrations(ctx, "cc", 42)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, errors.Is(err, ErrLightClientLag))
	require.Nil(t, regs)
	require.Equal(t, int32(1), stub.netCalls.Load(), "cancellation must stop retries promptly")
}
