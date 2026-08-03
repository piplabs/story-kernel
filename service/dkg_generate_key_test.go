package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// notFoundErr mimics the error GetDKGNetwork returns when the round's record is absent at
// the light client's verified height.
func notFoundErr() error {
	return fmt.Errorf("%w for code_commitment cc, round 42", story.ErrDKGNetworkNotFound)
}

// TestWaitForDKGNetworkCreation_Immediate verifies no retry happens when the round's network is
// already visible at the light client's verified height.
func TestWaitForDKGNetworkCreation_Immediate(t *testing.T) {
	stub := &stubQueryClient{networks: []*pb.DKGNetwork{{Round: 42}}}
	s := &DKGServer{QueryClient: stub}

	network, err := s.waitForDKGNetworkCreation(t.Context(), "cc", 42, 3, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, uint32(42), network.GetRound())
	require.Equal(t, int32(1), stub.netCalls.Load())
}

// TestWaitForDKGNetworkCreation_LagThenSuccess verifies the registration path outlasts a transient
// light-client lag: not-found reads are retried until the round becomes visible.
func TestWaitForDKGNetworkCreation_LagThenSuccess(t *testing.T) {
	stub := &stubQueryClient{
		netErrs:  []error{notFoundErr(), notFoundErr()}, // calls 1-2: light client still lagging
		networks: []*pb.DKGNetwork{{Round: 42}},         // call 3: caught up
	}
	s := &DKGServer{QueryClient: stub}

	network, err := s.waitForDKGNetworkCreation(t.Context(), "cc", 42, 5, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, uint32(42), network.GetRound())
	require.Equal(t, int32(3), stub.netCalls.Load(), "polls until the round is visible (2 lag + 1 caught up)")
}

// TestWaitForDKGNetworkCreation_RetryExhausted verifies that if the round never becomes visible,
// the call fails with ErrLightClientLag after the full retry budget.
func TestWaitForDKGNetworkCreation_RetryExhausted(t *testing.T) {
	stub := &stubQueryClient{netErr: notFoundErr()}
	s := &DKGServer{QueryClient: stub}

	network, err := s.waitForDKGNetworkCreation(t.Context(), "cc", 42, 4, time.Millisecond)
	require.Error(t, err)
	require.Nil(t, network)
	require.True(t, errors.Is(err, ErrLightClientLag), "exhaustion must preserve ErrLightClientLag")
	require.Equal(t, int32(4), stub.netCalls.Load())
}

// TestWaitForDKGNetworkCreation_OtherErrorFailsFast verifies a non-not-found query error is returned
// directly without burning the retry budget.
func TestWaitForDKGNetworkCreation_OtherErrorFailsFast(t *testing.T) {
	wantErr := errors.New("rpc down")
	stub := &stubQueryClient{netErr: wantErr}
	s := &DKGServer{QueryClient: stub}

	network, err := s.waitForDKGNetworkCreation(t.Context(), "cc", 42, 4, time.Millisecond)
	require.ErrorIs(t, err, wantErr)
	require.False(t, errors.Is(err, ErrLightClientLag))
	require.Nil(t, network)
	require.Equal(t, int32(1), stub.netCalls.Load(), "non-lag errors must not be retried")
}

// TestWaitForDKGNetworkCreation_ContextCanceled verifies a caller going away mid-wait stops the
// retry loop promptly instead of burning the remaining budget in an orphaned handler.
func TestWaitForDKGNetworkCreation_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	stub := &stubQueryClient{netErr: notFoundErr()}
	s := &DKGServer{QueryClient: stub}

	// A one-minute delay would time the test out if cancellation were not honored.
	network, err := s.waitForDKGNetworkCreation(ctx, "cc", 42, 5, time.Minute)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, errors.Is(err, ErrLightClientLag))
	require.Nil(t, network)
	require.Equal(t, int32(1), stub.netCalls.Load(), "cancellation must stop retries promptly")
}

// TestRegistrationRetryBudgetOutlastsObservedLag guards the retry budget against accidental
// shrinking: the light client has been observed to trail the tip by ~40s at round
// boundaries, so the total budget must stay comfortably above that.
func TestRegistrationRetryBudgetOutlastsObservedLag(t *testing.T) {
	budget := registrationNetworkRetryAttempts * registrationNetworkRetryDelay
	require.GreaterOrEqual(t, budget, 60*time.Second,
		"registration retry budget must outlast the ~40s observed light-client lag")
}
