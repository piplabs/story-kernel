package service

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/store"
)

const (
	// thresholdRetryAttempts is the number of retries when the on-chain threshold
	// is 0. This handles the case where the light client lags behind the chain
	// tip and hasn't yet observed the block where BeginDealing set the threshold.
	thresholdRetryAttempts = 5

	// thresholdRetryDelay is the delay between retries. The light client
	// refreshes every 3s, so 2s intervals ensure we observe the update promptly.
	thresholdRetryDelay = 2 * time.Second
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

	rc, err := s.fetchRoundContext(codeCommitmentsHex, round)
	if err != nil {
		return nil, err
	}

	// If threshold is still 0, the light client may be behind the chain tip.
	// Retry with backoff to allow it to catch up to the block where
	// BeginDealing set the threshold. Without this, kyber falls back to
	// MinimumT (n/2+1) which can differ from the on-chain threshold,
	// causing deal commitment length mismatches during resharing.
	if rc.Network.GetThreshold() == 0 {
		for attempt := range thresholdRetryAttempts {
			log.WithFields(log.Fields{
				"round":   round,
				"attempt": attempt + 1,
			}).Warn("GetOrLoadRoundContext: threshold is 0, retrying (light client may lag)")

			time.Sleep(thresholdRetryDelay)

			rc, err = s.fetchRoundContext(codeCommitmentsHex, round)
			if err != nil {
				return nil, err
			}

			if rc.Network.GetThreshold() > 0 {
				break
			}
		}

		if rc.Network.GetThreshold() == 0 {
			return nil, fmt.Errorf("threshold is 0 for round %d after %d retries; "+
				"light client may not have caught up to the dealing block", round, thresholdRetryAttempts)
		}
	}

	s.RoundCtxCache.Set(round, rc)

	return rc, nil
}

// fetchRoundContext queries on-chain DKG network state and registrations.
func (s *DKGServer) fetchRoundContext(
	codeCommitmentsHex string,
	round uint32,
) (*store.RoundContext, error) {
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

	return &store.RoundContext{
		Round:         round,
		Network:       network,
		Registrations: registrations,
		SortedPubKeys: sortedPubs,
	}, nil
}
