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

	// Error injection — when non-nil, the corresponding method returns this error
	// instead of normal data. Use Set*Error(err) to inject, Set*Error(nil) to clear.
	getDKGNetworkErr        error
	getDKGNetworkErrByRound map[uint32]error
	getRegistrationsErr     error
	verifyStartBlockErr     error
	getLatestActiveErr      error
	hasDecryptRequestErr    error
	hasDecryptRequestResult *bool
}

func NewMockQueryClient(network *pb.DKGNetwork) *MockQueryClient {
	return &MockQueryClient{
		network:                 network,
		registrations:           []*pb.DKGRegistration{},
		networkByRound:          make(map[uint32]*pb.DKGNetwork),
		registrationsByRound:    make(map[uint32][]*pb.DKGRegistration),
		getDKGNetworkErrByRound: make(map[uint32]error),
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

// --- Error injection setters ---

// SetGetDKGNetworkError injects an error for GetDKGNetwork. Pass nil to clear.
func (m *MockQueryClient) SetGetDKGNetworkError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getDKGNetworkErr = err
}

// SetGetDKGNetworkErrorForRound injects an error for GetDKGNetwork for a specific round.
// Pass nil to clear. Per-round errors take precedence over the global error.
func (m *MockQueryClient) SetGetDKGNetworkErrorForRound(round uint32, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.getDKGNetworkErrByRound, round)
	} else {
		m.getDKGNetworkErrByRound[round] = err
	}
}

// SetGetRegistrationsError injects an error for GetAllParticipantDKGRegistrations. Pass nil to clear.
func (m *MockQueryClient) SetGetRegistrationsError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getRegistrationsErr = err
}

// SetVerifyStartBlockError injects an error for VerifyStartBlock. Pass nil to clear.
func (m *MockQueryClient) SetVerifyStartBlockError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyStartBlockErr = err
}

// SetGetLatestActiveNetworkError injects an error for GetLatestActiveDKGNetwork. Pass nil to clear.
func (m *MockQueryClient) SetGetLatestActiveNetworkError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLatestActiveErr = err
}

// SetHasDecryptRequestError injects an error for HasDecryptRequest. Pass nil to clear.
func (m *MockQueryClient) SetHasDecryptRequestError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasDecryptRequestErr = err
}

// SetHasDecryptRequestResult overrides the return value of HasDecryptRequest.
func (m *MockQueryClient) SetHasDecryptRequestResult(exists bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasDecryptRequestResult = &exists
}

func (m *MockQueryClient) GetDKGNetwork(_ context.Context, _ string, round uint32) (*pb.DKGNetwork, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.getDKGNetworkErrByRound[round]; ok {
		return nil, err
	}
	if m.getDKGNetworkErr != nil {
		return nil, m.getDKGNetworkErr
	}
	if net, ok := m.networkByRound[round]; ok {
		return net, nil
	}
	return m.network, nil
}

func (m *MockQueryClient) GetAllParticipantDKGRegistrations(_ context.Context, _ string, round uint32) ([]*pb.DKGRegistration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getRegistrationsErr != nil {
		return nil, m.getRegistrationsErr
	}
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
	if m.getLatestActiveErr != nil {
		return nil, m.getLatestActiveErr
	}
	if m.latestActiveNetwork != nil {
		return m.latestActiveNetwork, nil
	}
	return m.network, nil
}

func (m *MockQueryClient) HasDecryptRequest(_ context.Context, _ uint32, _ string, _ string, _ string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.hasDecryptRequestErr != nil {
		return false, m.hasDecryptRequestErr
	}
	if m.hasDecryptRequestResult != nil {
		return *m.hasDecryptRequestResult, nil
	}
	return true, nil
}

func (m *MockQueryClient) VerifyStartBlock(_ context.Context, _ int64, _ []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifyStartBlockErr
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
