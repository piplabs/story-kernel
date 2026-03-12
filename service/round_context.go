package service

import (
	"context"

	"github.com/piplabs/story-kernel/store"
)

func (s *DKGServer) GetOrLoadRoundContext(
	codeCommitmentsHex string,
	round uint32,
) (*store.RoundContext, error) {
	if rc, ok := s.RoundCtxCache.Get(round); ok {
		// Do not return cached data if threshold is 0 (registration phase).
		// Threshold is set on-chain by BeginDealing after registration ends,
		// so a cached value of 0 is stale and must be refreshed.
		if rc.Network.GetThreshold() > 0 {
			return rc, nil
		}
	}

	network, err := s.QueryClient.GetDKGNetwork(context.Background(), codeCommitmentsHex, round)
	if err != nil {
		return nil, err
	}

	registrations, err := s.QueryClient.GetAllParticipantDKGRegistrations(
		context.Background(),
		codeCommitmentsHex,
		round,
	)
	if err != nil {
		return nil, err
	}

	sortedPubs, err := extractSortedPubKeys(s.Suite, registrations)
	if err != nil {
		return nil, err
	}

	rc := &store.RoundContext{
		Round:         round,
		Network:       network,
		Registrations: registrations,
		SortedPubKeys: sortedPubs,
	}

	s.RoundCtxCache.Set(round, rc)

	return rc, nil
}
