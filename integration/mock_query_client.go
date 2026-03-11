package integration

import (
	"context"
	"sync"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// MockQueryClient implements story.QueryClient for integration tests,
// avoiding dependency on a real CometBFT light client.
type MockQueryClient struct {
	mu sync.RWMutex

	// Primary (current round) network and registrations
	network       *pb.DKGNetwork
	registrations []*pb.DKGRegistration

	// Per-round overrides for multi-round scenarios (e.g. resharing)
	networkByRound       map[uint32]*pb.DKGNetwork
	registrationsByRound map[uint32][]*pb.DKGRegistration

	// Override for GetLatestActiveDKGNetwork (separate from current network)
	latestActiveNetwork *pb.DKGNetwork
}

func NewMockQueryClient(network *pb.DKGNetwork) *MockQueryClient {
	return &MockQueryClient{
		network:              network,
		registrations:        []*pb.DKGRegistration{},
		networkByRound:       make(map[uint32]*pb.DKGNetwork),
		registrationsByRound: make(map[uint32][]*pb.DKGRegistration),
	}
}

func (m *MockQueryClient) SetRegistrations(regs []*pb.DKGRegistration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registrations = regs
}

func (m *MockQueryClient) SetNetwork(net *pb.DKGNetwork) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.network = net
}

// SetRegistrationsByRound sets per-round registrations for multi-round scenarios.
func (m *MockQueryClient) SetRegistrationsByRound(round uint32, regs []*pb.DKGRegistration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registrationsByRound[round] = regs
}

// SetNetworkByRound sets a per-round network for multi-round scenarios.
func (m *MockQueryClient) SetNetworkByRound(round uint32, net *pb.DKGNetwork) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.networkByRound[round] = net
}

// SetLatestActiveNetwork overrides what GetLatestActiveDKGNetwork returns.
func (m *MockQueryClient) SetLatestActiveNetwork(net *pb.DKGNetwork) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latestActiveNetwork = net
}

func (m *MockQueryClient) GetDKGNetwork(_ context.Context, _ string, round uint32) (*pb.DKGNetwork, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if net, ok := m.networkByRound[round]; ok {
		return net, nil
	}
	return m.network, nil
}

func (m *MockQueryClient) GetAllVerifiedDKGRegistrations(_ context.Context, _ string, round uint32) ([]*pb.DKGRegistration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Check per-round override first
	if regs, ok := m.registrationsByRound[round]; ok {
		out := make([]*pb.DKGRegistration, len(regs))
		copy(out, regs)
		return out, nil
	}
	// Return a copy to avoid races
	regs := make([]*pb.DKGRegistration, len(m.registrations))
	copy(regs, m.registrations)
	return regs, nil
}

func (m *MockQueryClient) GetLatestActiveDKGNetwork(_ context.Context) (*pb.DKGNetwork, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.latestActiveNetwork != nil {
		return m.latestActiveNetwork, nil
	}
	return m.network, nil
}

func (m *MockQueryClient) VerifyStartBlock(_ context.Context, _ int64, _ []byte) error {
	return nil
}

func (m *MockQueryClient) Close() error {
	return nil
}

// GetCurrentRegistrations returns a copy of the current (non-round-specific) registrations.
func (m *MockQueryClient) GetCurrentRegistrations() []*pb.DKGRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	regs := make([]*pb.DKGRegistration, len(m.registrations))
	copy(regs, m.registrations)
	return regs
}
