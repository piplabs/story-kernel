package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
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

// ErrLightClientLag is the sentinel for light-client-lag-induced fetch failures.
var ErrLightClientLag = errors.New("light client appears to lag chain tip")

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
	if err != nil && !errors.Is(err, ErrLightClientLag) {
		return nil, err
	}

	// If threshold is still 0, the light client may be behind the chain tip.
	// Retry with backoff to allow it to catch up to the block where
	// BeginDealing set the threshold. Without this, kyber falls back to
	// MinimumT (n/2+1) which can differ from the on-chain threshold,
	// causing deal commitment length mismatches during resharing.
	if err != nil || rc.Network.GetThreshold() == 0 {
		for attempt := range thresholdRetryAttempts {
			log.WithFields(log.Fields{
				"round":   round,
				"attempt": attempt + 1,
			}).Warn("GetOrLoadRoundContext: threshold is 0, retrying (light client may lag)")

			time.Sleep(thresholdRetryDelay)

			rc, err = s.fetchRoundContext(codeCommitmentsHex, round)
			if err != nil && !errors.Is(err, ErrLightClientLag) {
				return nil, err
			}
			if err == nil && rc.Network.GetThreshold() > 0 {
				break
			}
		}

		if err != nil {
			return nil, fmt.Errorf("%w: round %d after %d retries: %v",
				ErrLightClientLag, round, thresholdRetryAttempts, err)
		}
		if rc.Network.GetThreshold() == 0 {
			return nil, fmt.Errorf("%w: round %d threshold still 0 after %d retries",
				ErrLightClientLag, round, thresholdRetryAttempts)
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

	if err := validateRegistrations(registrations, network, round); err != nil {
		return nil, fmt.Errorf("registration validation failed: %w", err)
	}

	sortedPubs, err := extractSortedPubKeys(s.Suite, registrations)
	if err != nil {
		return nil, err
	}

	// DEBUG (Bug2): the roundContext committee is the chain-fetch, post-filter set
	// (INVALIDATED dropped). SortedPubKeys here feeds GetInitDKG/Finalize as
	// NewNodes; compare against the sealed store-rebuild committee for the same
	// round to detect the invalidated-node divergence.
	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentsHex,
		"round":           round,
		"total":           network.GetTotal(),
		"threshold":       network.GetThreshold(),
		"is_resharing":    network.GetIsResharing(),
		"committee":       fmtRegs(registrations),
		"sorted_pub_keys": fmtPubKeys(sortedPubs),
		"source":          "chain-fetch roundContext (filtered)",
	}).Info("fetchRoundContext: assembled round context")

	return &store.RoundContext{
		Round:         round,
		Network:       network,
		Registrations: registrations,
		SortedPubKeys: sortedPubs,
	}, nil
}

// validateRegistrations checks that the fetched registrations are consistent
// with the on-chain network state before they are used to build DKG state.
func validateRegistrations(regs []*pb.DKGRegistration, network *pb.DKGNetwork, round uint32) error {
	// Light client behind BeginDealing: regs visible but Total not yet persisted.
	if network.GetTotal() == 0 && len(regs) > 0 {
		return fmt.Errorf("%w: %d registrations visible but network.Total=0",
			ErrLightClientLag, len(regs))
	}

	// Registration count must match the network's expected total.
	if uint32(len(regs)) != network.GetTotal() {
		return fmt.Errorf("registration count %d does not match network total %d",
			len(regs), network.GetTotal())
	}

	// No duplicate Index values allowed.
	seen := make(map[uint32]struct{}, len(regs))
	for _, reg := range regs {
		if _, exists := seen[reg.GetIndex()]; exists {
			return fmt.Errorf("duplicate registration index %d", reg.GetIndex())
		}
		seen[reg.GetIndex()] = struct{}{}
	}

	// Each registration's Round must match the requested round.
	for _, reg := range regs {
		if reg.GetRound() != round {
			return fmt.Errorf("registration round %d does not match requested round %d (validator %s)",
				reg.GetRound(), round, reg.GetValidatorAddr())
		}
	}

	return nil
}
