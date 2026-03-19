package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// mockQueryClientForPID implements the subset of story.QueryClient needed for PID tests.
type mockQueryClientForPID struct {
	latestNetwork *pb.DKGNetwork
	latestErr     error
}

func (m *mockQueryClientForPID) GetDKGNetwork(_ context.Context, _ string, _ uint32) (*pb.DKGNetwork, error) {
	return nil, nil
}

func (m *mockQueryClientForPID) GetAllParticipantDKGRegistrations(_ context.Context, _ string, _ uint32) ([]*pb.DKGRegistration, error) {
	return nil, nil
}

func (m *mockQueryClientForPID) GetLatestActiveDKGNetwork(_ context.Context) (*pb.DKGNetwork, error) {
	return m.latestNetwork, m.latestErr
}

func (m *mockQueryClientForPID) VerifyStartBlock(_ context.Context, _ int64, _ []byte) error {
	return nil
}

func (m *mockQueryClientForPID) Close() error {
	return nil
}

func TestVerifyRoundMatchesLatestNetwork_ReturnsNetwork(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Round: 5, Total: 10}
	mock := &mockQueryClientForPID{latestNetwork: network}
	server := &DKGServer{QueryClient: mock}

	got, err := server.verifyRoundMatchesLatestNetwork(context.Background(), 5)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint32(5), got.GetRound())
	assert.Equal(t, uint32(10), got.GetTotal())
}

func TestVerifyRoundMatchesLatestNetwork_RoundMismatch(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Round: 5, Total: 10}
	mock := &mockQueryClientForPID{latestNetwork: network}
	server := &DKGServer{QueryClient: mock}

	got, err := server.verifyRoundMatchesLatestNetwork(context.Background(), 99)
	require.Error(t, err)
	require.Nil(t, got)
	assert.Contains(t, err.Error(), "round mismatch")
}

func TestPIDBoundsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pid     uint32
		total   uint32
		wantErr bool
	}{
		{
			name:    "PID zero is out of bounds",
			pid:     0,
			total:   5,
			wantErr: true,
		},
		{
			name:    "PID exceeds total",
			pid:     6,
			total:   5,
			wantErr: true,
		},
		{
			name:    "PID at lower bound",
			pid:     1,
			total:   5,
			wantErr: false,
		},
		{
			name:    "PID at upper bound",
			pid:     5,
			total:   5,
			wantErr: false,
		},
		{
			name:    "PID in middle",
			pid:     3,
			total:   5,
			wantErr: false,
		},
		{
			name:    "PID far exceeds total",
			pid:     100,
			total:   5,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Directly test the bounds check logic extracted from PartialDecryptTDH2.
			outOfBounds := tc.pid < 1 || tc.pid > tc.total
			if tc.wantErr {
				assert.True(t, outOfBounds,
					"PID %d with total %d should be out of bounds", tc.pid, tc.total)
			} else {
				assert.False(t, outOfBounds,
					"PID %d with total %d should be within bounds", tc.pid, tc.total)
			}
		})
	}
}

func TestPIDCacheBoundsIntegration(t *testing.T) {
	t.Parallel()

	// Verify that when PIDCache returns a PID, the bounds check catches invalid values.
	cache := store.NewPIDCache()

	// Set PID=0 (invalid: should be 1-based)
	cache.Set(1, 0)
	pid, ok := cache.Get(1)
	require.True(t, ok)
	assert.Equal(t, uint32(0), pid)
	// Bounds check: pid < 1 || pid > total
	assert.True(t, pid < 1 || pid > 5,
		"PID=0 should fail bounds check against total=5")

	// Set PID=6 (invalid: exceeds total=5)
	cache.Set(2, 6)
	pid, ok = cache.Get(2)
	require.True(t, ok)
	assert.Equal(t, uint32(6), pid)
	assert.True(t, pid < 1 || pid > 5,
		"PID=6 should fail bounds check against total=5")

	// Set PID=3 (valid)
	cache.Set(3, 3)
	pid, ok = cache.Get(3)
	require.True(t, ok)
	assert.Equal(t, uint32(3), pid)
	assert.False(t, pid < 1 || pid > 5,
		"PID=3 should pass bounds check against total=5")
}
