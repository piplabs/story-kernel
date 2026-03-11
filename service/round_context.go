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
		return rc, nil
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
