package service

import (
	"context"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

////////////////////////////////////////////////////////////////////////////////
// Initial DKG
////////////////////////////////////////////////////////////////////////////////

// GetInitDKG returns the Distributed Key Generator for an initial (non-resharing)
// DKG round.
//
// Resolution order:
//  1. In-memory cache
//  2. Persistent state -> rebuild
//  3. Fresh build (first time initialization)
//
// This function is the ONLY entry point for accessing initial-round DKGs.
func (s *DKGServer) GetInitDKG(
	codeCommitmentHex string,
	round, threshold uint32,
	nextPubs []kyber.Point,
) (*dkg.DistKeyGenerator, error) {
	if dkgInst, ok := s.InitDKGCache.Get(round); ok {
		return dkgInst, nil
	}

	exists, err := s.DKGStore.HasDKGState(codeCommitmentHex, round)
	if err != nil {
		return nil, err
	}

	var dkgInst *dkg.DistKeyGenerator

	if exists {
		dkgInst, err = s.rebuildInitDKG(codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}
	} else {
		dkgInst, err = s.buildInitDKG(codeCommitmentHex, round, threshold, nextPubs)
		if err != nil {
			return nil, err
		}
	}

	s.InitDKGCache.Set(round, dkgInst)

	return dkgInst, nil
}

// buildInitDKG creates a new initial DKG.
// It MUST be called only when no prior DKG state exists.
func (s *DKGServer) buildInitDKG(
	codeCommitmentHex string,
	round, threshold uint32,
	nextPubs []kyber.Point,
) (*dkg.DistKeyGenerator, error) {
	longterm, err := s.LoadLongtermKey(codeCommitmentHex, round)
	if err != nil {
		return nil, errors.Wrapf(err, "load Ed25519 key (round=%d)", round)
	}

	// Threshold=0 lets kyber default to MinimumT(len(participants)), ensuring
	// consistency across all DKG participants regardless of on-chain state timing.
	// The on-chain operational threshold is enforced at the protocol level, not here.
	return dkg.NewDistKeyGenerator(
		s.Suite,
		longterm,
		nextPubs,
		0,
	)
}

// rebuildInitDKG reconstructs the initial DKG from persisted state.
func (s *DKGServer) rebuildInitDKG(
	codeCommitmentHex string,
	round uint32,
) (*dkg.DistKeyGenerator, error) {
	st, err := s.DKGStore.LoadDKGState(codeCommitmentHex, round)
	if err != nil {
		return nil, err
	}

	longterm, err := s.LoadLongtermKey(codeCommitmentHex, round)
	if err != nil {
		return nil, err
	}

	// Threshold=0 lets kyber default to MinimumT(len(participants)).
	// See buildInitDKG for rationale.
	dkgInst, err := dkg.NewDistKeyGenerator(
		s.Suite,
		longterm,
		st.PubKeys,
		0,
	)
	if err != nil {
		return nil, err
	}

	replayMessages(dkgInst, st)

	return dkgInst, nil
}

////////////////////////////////////////////////////////////////////////////////
// Resharing – Previous DKG
////////////////////////////////////////////////////////////////////////////////

// GetResharingPrevDKG returns the "previous committee" DKG handler used during
// resharing.
//
// This DKG is responsible for producing shares for the new committee.
func (s *DKGServer) GetResharingPrevDKG(
	codeCommitmentHex string,
	toRound, nextThreshold uint32,
	nextPubs []kyber.Point,
	latest *pb.DKGNetwork,
) (*dkg.DistKeyGenerator, error) {
	fromRound := latest.GetRound()

	if dkgInst, ok := s.ResharingPrevCache.Get(fromRound, toRound); ok {
		return dkgInst, nil
	}

	// check prev and next state
	existsPrev, err := s.DKGStore.HasDKGState(codeCommitmentHex, fromRound)
	if err != nil {
		return nil, err
	}

	existsNext, err := s.DKGStore.HasDKGState(codeCommitmentHex, toRound)
	if err != nil {
		return nil, err
	}

	var dkgInst *dkg.DistKeyGenerator

	if existsPrev && existsNext {
		dkgInst, err = s.rebuildResharingPrevDKG(codeCommitmentHex, fromRound, toRound)
		if err != nil {
			return nil, err
		}
	} else {
		prevPubs, publicCoeffs, err := s.fetchLatestPubKeysAndCoeffs(codeCommitmentHex, latest)
		if err != nil {
			return nil, err
		}

		dkgInst, err = s.buildResharingPrevDKG(
			codeCommitmentHex,
			fromRound,
			nextThreshold,
			prevPubs,
			nextPubs,
			latest.GetIsResharing(),
		)
		if err != nil {
			return nil, err
		}

		if err := s.DKGStore.SetPrevDKGState(
			codeCommitmentHex,
			fromRound,
			latest.GetThreshold(),
			prevPubs,
			publicCoeffs,
		); err != nil {
			return nil, err
		}

		if err := s.DKGStore.SetNextDKGState(
			codeCommitmentHex,
			fromRound,
			toRound,
			nextThreshold,
			nextPubs,
		); err != nil {
			return nil, err
		}
	}

	s.ResharingPrevCache.Set(fromRound, toRound, dkgInst)

	return dkgInst, nil
}

// buildResharingPrevDKG builds the resharing DKG for the previous committee.
func (s *DKGServer) buildResharingPrevDKG(
	codeCommitmentHex string,
	fromRound, nextT uint32,
	prevPubs, nextPubs []kyber.Point,
	isResharing bool,
) (*dkg.DistKeyGenerator, error) {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, fromRound)
	if err != nil {
		return nil, err
	}

	var (
		existing *dkg.DistKeyGenerator
		ok       bool
	)

	// NOTE:
	// This function may reuse an existing in-memory DKG instance if available.
	// The cache lookup here is NOT an optimization, but a semantic check to reuse
	// an already-built DKG execution context when possible.
	if !isResharing {
		existing, ok = s.InitDKGCache.Get(fromRound)
		if !ok {
			existing, err = s.rebuildInitDKG(codeCommitmentHex, fromRound)
			if err != nil {
				return nil, err
			}
		}
		s.InitDKGCache.Set(fromRound, existing)
	} else {
		existing, ok = s.ResharingNextCache.Get(fromRound)
		if !ok {
			existing, err = s.rebuildResharingNextDKG(codeCommitmentHex, fromRound)
			if err != nil {
				return nil, err
			}
		}
		s.ResharingNextCache.Set(fromRound, existing)
	}

	share, err := existing.DistKeyShare()
	if err != nil {
		return nil, err
	}

	// OldThreshold must equal len(share.Commits), which is the kyber cryptographic
	// threshold. share.Commits is the polynomial commitment from the previous DKG
	// round and has the same semantics as PublicCoeffs. Using the on-chain
	// operational threshold causes an index-out-of-range panic in kyber.
	oldThreshold := len(share.Commits)

	// Threshold=0 lets kyber default to MinimumT(len(NewNodes)), ensuring the
	// new polynomial degree is consistent across all participants. The on-chain
	// operational threshold (nextT) is NOT suitable here — it can differ from the
	// cryptographic threshold used by kyber, causing index-out-of-range panics
	// in resharingKey() when deal.Commitments length doesn't match d.newT.
	return dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevPubs,
		NewNodes:     nextPubs,
		Share:        share,
		Threshold:    0,
		OldThreshold: oldThreshold,
	})
}

// rebuildResharingPrevDKG reconstructs the previous-committee DKG from state.
func (s *DKGServer) rebuildResharingPrevDKG(
	codeCommitmentHex string,
	fromRound, toRound uint32,
) (*dkg.DistKeyGenerator, error) {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, fromRound)
	if err != nil {
		return nil, err
	}

	prevState, err := s.DKGStore.LoadDKGState(codeCommitmentHex, fromRound)
	if err != nil {
		return nil, err
	}

	nextState, err := s.DKGStore.LoadDKGState(codeCommitmentHex, toRound)
	if err != nil {
		return nil, err
	}

	var (
		existing *dkg.DistKeyGenerator
		ok       bool
	)

	// NOTE:
	// This function may reuse an existing in-memory DKG instance if available.
	// The cache lookup here is NOT an optimization, but a semantic check to reuse
	// an already-built DKG execution context when possible.
	existing, ok = s.ResharingNextCache.Get(fromRound)
	if !ok {
		existing, err = s.rebuildResharingNextDKG(codeCommitmentHex, fromRound)
		if err != nil {
			return nil, err
		}
		s.ResharingNextCache.Set(fromRound, existing)
	}

	share, err := existing.DistKeyShare()
	if err != nil {
		return nil, err
	}

	// OldThreshold must equal len(share.Commits), which is the kyber cryptographic
	// threshold. See buildResharingPrevDKG for details.
	oldThreshold := len(share.Commits)

	// Threshold=0 lets kyber default to MinimumT(len(NewNodes)).
	// See buildResharingPrevDKG for rationale.
	dkgInst, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevState.PubKeys,
		NewNodes:     nextState.PubKeys,
		Share:        share,
		Threshold:    0,
		OldThreshold: oldThreshold,
	})
	if err != nil {
		return nil, err
	}

	for _, r := range nextState.Responses {
		_, _ = dkgInst.ProcessResponse(&r)
	}

	return dkgInst, nil
}

////////////////////////////////////////////////////////////////////////////////
// Resharing – Next DKG
////////////////////////////////////////////////////////////////////////////////

// GetResharingNextDKG returns the "next committee" DKG handler used during resharing.
func (s *DKGServer) GetResharingNextDKG(
	codeCommitmentHex string,
	round, threshold uint32,
	nextPubs []kyber.Point,
) (*dkg.DistKeyGenerator, error) {
	if dkgInst, ok := s.ResharingNextCache.Get(round); ok {
		log.WithFields(log.Fields{
			"code_commitment": codeCommitmentHex,
			"round":           round,
			"verifiers_count": len(dkgInst.Verifiers()),
		}).Info("DEBUG: GetResharingNextDKG cache HIT")

		return dkgInst, nil
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           round,
	}).Info("DEBUG: GetResharingNextDKG cache MISS")

	stNext, err := s.DKGStore.LoadDKGState(codeCommitmentHex, round)
	if err != nil {
		return nil, err
	}

	existsPrev, err := s.DKGStore.HasDKGState(codeCommitmentHex, stNext.FromRound)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"code_commitment":   codeCommitmentHex,
		"round":             round,
		"stNext_threshold":  stNext.Threshold,
		"stNext_pubkeys":    len(stNext.PubKeys),
		"stNext_from_round": stNext.FromRound,
		"existsPrev":        existsPrev,
	}).Info("DEBUG: GetResharingNextDKG state check")

	var dkgInst *dkg.DistKeyGenerator

	if stNext.Threshold != 0 && len(stNext.PubKeys) != 0 && existsPrev {
		log.Info("DEBUG: GetResharingNextDKG taking REBUILD path")
		dkgInst, err = s.rebuildResharingNextDKG(codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}
	} else {
		log.Info("DEBUG: GetResharingNextDKG taking BUILD path")
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"latest_round":      latest.GetRound(),
			"latest_threshold":  latest.GetThreshold(),
			"latest_total":      latest.GetTotal(),
			"latest_active_set": len(latest.GetActiveValSet()),
		}).Info("DEBUG: GetResharingNextDKG latest active network")

		prevPubs, publicCoeffs, err := s.fetchLatestPubKeysAndCoeffs(codeCommitmentHex, latest)
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"prevPubs_len":     len(prevPubs),
			"publicCoeffs_len": len(publicCoeffs),
		}).Info("DEBUG: GetResharingNextDKG fetched prev data")

		dkgInst, err = s.buildResharingNextDKG(
			codeCommitmentHex,
			round,
			threshold,
			prevPubs,
			nextPubs,
			publicCoeffs,
		)
		if err != nil {
			return nil, err
		}

		if err := s.DKGStore.SetNextDKGState(
			codeCommitmentHex,
			latest.GetRound(),
			round,
			threshold,
			nextPubs,
		); err != nil {
			return nil, err
		}
	}

	s.ResharingNextCache.Set(round, dkgInst)

	return dkgInst, nil
}

// buildResharingNextDKG builds the resharing DKG for the next committee.
func (s *DKGServer) buildResharingNextDKG(codeCommitmentHex string, round, nextT uint32, prevPubs, nextPubs, publicCoeffs []kyber.Point) (*dkg.DistKeyGenerator, error) {
	// Load longterm key (Ed25519)
	longterm, err := s.LoadLongtermKey(codeCommitmentHex, round)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load sealed Ed25519 private key for code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	// OldThreshold must equal len(PublicCoeffs), which is the kyber cryptographic
	// threshold (degree of the polynomial + 1). This differs from the on-chain
	// operational threshold stored in DKGNetwork. Using the on-chain threshold
	// causes an index-out-of-range panic inside kyber's resharingKey().
	oldThreshold := len(publicCoeffs)

	// Create the next DKG
	log.WithFields(log.Fields{
		"code_commitment":  codeCommitmentHex,
		"round":            round,
		"oldThreshold":     oldThreshold,
		"nextT":            nextT,
		"prevPubs_len":     len(prevPubs),
		"nextPubs_len":     len(nextPubs),
		"publicCoeffs_len": len(publicCoeffs),
	}).Info("DEBUG: buildResharingNextDKG parameters")

	// Threshold=0 lets kyber default to MinimumT(len(NewNodes)), ensuring the
	// new polynomial degree matches what dealers actually produce in their deals.
	// See buildResharingPrevDKG for detailed rationale.
	nextDKG, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevPubs,
		NewNodes:     nextPubs,
		PublicCoeffs: publicCoeffs,
		Threshold:    0,
		OldThreshold: oldThreshold,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build a next DKG for resharing, code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	return nextDKG, nil
}

// rebuildResharingNextDKG reconstructs the next-committee DKG from state.
func (s *DKGServer) rebuildResharingNextDKG(
	codeCommitmentHex string,
	toRound uint32,
) (*dkg.DistKeyGenerator, error) {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, toRound)
	if err != nil {
		return nil, err
	}

	nextState, err := s.DKGStore.LoadDKGState(codeCommitmentHex, toRound)
	if err != nil {
		return nil, err
	}

	prevState, err := s.DKGStore.LoadDKGState(codeCommitmentHex, nextState.FromRound)
	if err != nil {
		return nil, err
	}

	// OldThreshold must equal len(PublicCoeffs), which is the kyber cryptographic
	// threshold. See buildResharingNextDKG for details.
	oldThreshold := len(prevState.PublicCoeffs)

	// Threshold=0 lets kyber default to MinimumT(len(NewNodes)).
	// See buildResharingNextDKG for rationale.
	dkgInst, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevState.PubKeys,
		NewNodes:     nextState.PubKeys,
		PublicCoeffs: prevState.PublicCoeffs,
		Threshold:    0,
		OldThreshold: oldThreshold,
	})
	if err != nil {
		return nil, err
	}

	replayMessages(dkgInst, nextState)

	return dkgInst, nil
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

// replayMessages replays persisted DKG deals, responses, and justifications
// into a DKG instance to restore its state after a restart.
func replayMessages(
	dkgInst *dkg.DistKeyGenerator,
	st *store.DKGState,
) {
	for _, d := range st.Deals {
		_, _ = dkgInst.ProcessDeal(&d)
	}
	for _, r := range st.Responses {
		_, _ = dkgInst.ProcessResponse(&r)
	}
	for _, j := range st.Justifications {
		_ = dkgInst.ProcessJustification(&j)
	}
}

func (s *DKGServer) fetchLatestPubKeysAndCoeffs(
	codeCommitmentHex string,
	latest *pb.DKGNetwork,
) ([]kyber.Point, []kyber.Point, error) {
	prevRegs, err := s.QueryClient.GetAllParticipantDKGRegistrations(
		context.Background(),
		codeCommitmentHex,
		latest.GetRound(),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get previous DKG registrations")
	}

	prevPubs, err := extractSortedPubKeys(s.Suite, prevRegs)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to extract previous public keys")
	}

	publicCoeffs, err := UnmarshalPoints(s.Suite, latest.GetPublicCoeffs())
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal public coefficients")
	}

	return prevPubs, publicCoeffs, nil
}
