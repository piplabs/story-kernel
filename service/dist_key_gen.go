package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
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

	// Serialize per-round to prevent concurrent RPCs from both observing a
	// cache miss and racing to build+save the same DKG state.
	mu := s.getInitDKGMu(round)
	mu.Lock()
	defer mu.Unlock()

	// Re-check cache after acquiring lock; another goroutine may have populated it.
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

		// Persist threshold and pub keys so the DKG can be rebuilt after
		// a kernel restart. Without this, HasDKGState returns false (threshold=0,
		// pubkeys=nil) and rebuildInitDKG cannot reconstruct the instance.
		if err := s.DKGStore.SaveDKGState(&store.DKGState{
			Threshold: threshold,
			PubKeys:   nextPubs,
		}, codeCommitmentHex, round); err != nil {
			return nil, errors.Wrapf(err, "persist initial DKG state (round=%d)", round)
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
	if threshold == 0 {
		return nil, errors.Errorf("threshold must be > 0 for initial DKG (round=%d); on-chain threshold may not be set yet", round)
	}

	longterm, err := s.LoadLongtermKey(codeCommitmentHex, round)
	if err != nil {
		return nil, errors.Wrapf(err, "load Ed25519 key (round=%d)", round)
	}

	return dkg.NewDistKeyGenerator(
		s.Suite,
		longterm,
		nextPubs,
		int(threshold),
	)
}

// rebuildInitDKG reconstructs the initial DKG from persisted state.
//
// When persisted PrivateCoeffs are available, the dealer's polynomial is
// restored to the original one that was used to generate deals. This is
// critical because NewDistKeyGenerator generates a new random polynomial,
// which would cause session ID and commitment mismatches with peers who
// already received deals generated from the original polynomial.
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

	dkgInst, err := dkg.NewDistKeyGenerator(
		s.Suite,
		longterm,
		st.PubKeys,
		int(st.Threshold),
	)
	if err != nil {
		return nil, err
	}

	// Restore the original dealer polynomial from sealed storage before replaying
	// messages. This must happen before replayMessages because response verification
	// in dealer.ProcessResponse checks session ID, which depends on the polynomial's
	// public commitments.
	coeffs, loadErr := s.DKGStore.LoadPrivateCoeffs(codeCommitmentHex, round)
	if loadErr != nil {
		log.Errorf("failed to load sealed private coeffs (round=%d): %v — DKG may produce mismatched results", round, loadErr)
	} else if len(coeffs) > 0 {
		if err := restoreDealerPoly(s.Suite, dkgInst, coeffs); err != nil {
			log.Errorf("failed to restore dealer polynomial (round=%d): %v — DKG may produce mismatched results", round, err)
		} else {
			log.WithField("round", round).Info("restored dealer polynomial from sealed coefficients")

			// [DEBUG] Log verifier state BEFORE Deals()
			log.Infof("[DEBUG-REBUILD] before Deals(): verifier count=%d", len(dkgInst.Verifiers()))
			for idx, v := range dkgInst.Verifiers() {
				log.Infof("[DEBUG-REBUILD] before Deals(): verifiers[%d] hasDeal=%v responses=%d",
					idx, v.Deal() != nil, len(v.Responses()))
			}

			// Process the self-deal into verifiers[self] before replaying messages.
			if _, err := dkgInst.Deals(); err != nil {
				log.Errorf("failed to process self-deal after polynomial restore (round=%d): %v", round, err)
			}

			// [DEBUG] Log verifier state AFTER Deals()
			for idx, v := range dkgInst.Verifiers() {
				log.Infof("[DEBUG-REBUILD] after Deals(): verifiers[%d] hasDeal=%v responses=%d certified=%v",
					idx, v.Deal() != nil, len(v.Responses()), v.DealCertified())
			}
		}
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

	mu := s.getResharePrevMu(fromRound, toRound)
	mu.Lock()
	defer mu.Unlock()

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
			latest.GetThreshold(),
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
	fromRound, prevT, nextT uint32,
	prevPubs, nextPubs []kyber.Point,
	isResharing bool,
) (*dkg.DistKeyGenerator, error) {
	if nextT == 0 {
		return nil, errors.Errorf("nextT must be > 0 for resharing prev DKG (fromRound=%d); on-chain threshold may not be set yet", fromRound)
	}
	if prevT == 0 {
		return nil, errors.Errorf("prevT must be > 0 for resharing prev DKG (fromRound=%d)", fromRound)
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"from_round":      fromRound,
		"prevT":           prevT,
		"nextT":           nextT,
		"num_prevPubs":    len(prevPubs),
		"num_nextPubs":    len(nextPubs),
		"is_resharing":    isResharing,
	}).Info("buildResharingPrevDKG: creating DKG handler")
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

	return dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevPubs,
		NewNodes:     nextPubs,
		Share:        share,
		Threshold:    int(nextT),
		OldThreshold: int(prevT),
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

	dkgInst, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevState.PubKeys,
		NewNodes:     nextState.PubKeys,
		Share:        share,
		Threshold:    int(nextState.Threshold),
		OldThreshold: int(prevState.Threshold),
	})
	if err != nil {
		return nil, err
	}

	// Restore the dealer polynomial for resharing prev DKG.
	// Same issue as rebuildInitDKG: NewDistKeyHandler generates a new random
	// polynomial (only Share.V is reused as the secret coefficient, but the
	// remaining t-1 coefficients are random), producing different commitments
	// and session ID. Peers' responses reference the original session ID, so
	// the dealer must be restored to the original polynomial.
	//
	// The coefficients are persisted under toRound because GenerateDeals
	// stores them with req.GetRound() (which equals toRound for resharing).
	coeffs, loadErr := s.DKGStore.LoadPrivateCoeffs(codeCommitmentHex, toRound)
	if loadErr != nil {
		log.Errorf("failed to load sealed private coeffs for resharing prev DKG (toRound=%d): %v", toRound, loadErr)
	} else if len(coeffs) > 0 {
		if err := restoreDealerPoly(s.Suite, dkgInst, coeffs); err != nil {
			log.Errorf("failed to restore dealer polynomial for resharing prev DKG (toRound=%d): %v", toRound, err)
		} else {
			log.WithField("toRound", toRound).Info("restored dealer polynomial for resharing prev DKG")
			// Process the self-deal into verifiers[self] when the node is in
			// both old and new lists (newPresent=true). Deals() is safe to call
			// even when newPresent=false — it simply returns deals without
			// self-processing.
			if _, err := dkgInst.Deals(); err != nil {
				log.Errorf("failed to process self-deal after polynomial restore for resharing prev DKG (toRound=%d): %v", toRound, err)
			}
		}
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
		return dkgInst, nil
	}

	mu := s.getReshareNextMu(round)
	mu.Lock()
	defer mu.Unlock()

	if dkgInst, ok := s.ResharingNextCache.Get(round); ok {
		return dkgInst, nil
	}

	stNext, err := s.DKGStore.LoadDKGState(codeCommitmentHex, round)
	if err != nil {
		return nil, err
	}

	existsPrev, err := s.DKGStore.HasDKGState(codeCommitmentHex, stNext.FromRound)
	if err != nil {
		return nil, err
	}

	var dkgInst *dkg.DistKeyGenerator

	if stNext.Threshold != 0 && len(stNext.PubKeys) != 0 && existsPrev {
		dkgInst, err = s.rebuildResharingNextDKG(codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			return nil, err
		}

		prevPubs, publicCoeffs, err := s.fetchLatestPubKeysAndCoeffs(codeCommitmentHex, latest)
		if err != nil {
			return nil, err
		}

		dkgInst, err = s.buildResharingNextDKG(
			codeCommitmentHex,
			round,
			latest.GetThreshold(),
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
func (s *DKGServer) buildResharingNextDKG(codeCommitmentHex string, round, prevT, nextT uint32, prevPubs, nextPubs, publicCoeffs []kyber.Point) (*dkg.DistKeyGenerator, error) {
	if nextT == 0 {
		return nil, errors.Errorf("nextT must be > 0 for resharing next DKG (round=%d); on-chain threshold may not be set yet", round)
	}
	if prevT == 0 {
		return nil, errors.Errorf("prevT must be > 0 for resharing next DKG (round=%d)", round)
	}

	// Load longterm key (Ed25519)
	longterm, err := s.LoadLongtermKey(codeCommitmentHex, round)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load sealed Ed25519 private key for code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	log.WithFields(log.Fields{
		"code_commitment":  codeCommitmentHex,
		"round":            round,
		"prevT":            prevT,
		"nextT":            nextT,
		"num_prevPubs":     len(prevPubs),
		"num_nextPubs":     len(nextPubs),
		"num_publicCoeffs": len(publicCoeffs),
	}).Info("buildResharingNextDKG: creating DKG handler")
	// Create the next DKG
	nextDKG, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevPubs,
		NewNodes:     nextPubs,
		PublicCoeffs: publicCoeffs,
		Threshold:    int(nextT),
		OldThreshold: int(prevT),
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

	dkgInst, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        s.Suite,
		Longterm:     longterm,
		OldNodes:     prevState.PubKeys,
		NewNodes:     nextState.PubKeys,
		PublicCoeffs: prevState.PublicCoeffs,
		Threshold:    int(nextState.Threshold),
		OldThreshold: int(prevState.Threshold),
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
	log.Infof("[DEBUG-REPLAY] starting replayMessages: deals=%d responses=%d justifications=%d",
		len(st.Deals), len(st.Responses), len(st.Justifications))

	for i, d := range st.Deals {
		resp, err := dkgInst.ProcessDeal(&d)
		if err != nil {
			log.Errorf("[DEBUG-REPLAY] ProcessDeal[%d] dealer=%d FAILED: %v", i, d.Index, err)
		} else {
			status := "approval"
			if resp != nil && resp.Response != nil && !resp.Response.Status {
				status = "complaint"
			}
			log.Infof("[DEBUG-REPLAY] ProcessDeal[%d] dealer=%d → %s", i, d.Index, status)
		}
	}

	for i, r := range st.Responses {
		j, err := dkgInst.ProcessResponse(&r)
		if err != nil {
			log.Errorf("[DEBUG-REPLAY] ProcessResponse[%d] dealer=%d responder=%d status=%v FAILED: %v",
				i, r.Index, r.Response.Index, r.Response.Status, err)
		} else {
			hasJust := j != nil
			log.Infof("[DEBUG-REPLAY] ProcessResponse[%d] dealer=%d responder=%d status=%v justification=%v",
				i, r.Index, r.Response.Index, r.Response.Status, hasJust)
		}
	}

	for i, j := range st.Justifications {
		err := dkgInst.ProcessJustification(&j)
		if err != nil {
			log.Errorf("[DEBUG-REPLAY] ProcessJustification[%d] dealer=%d complainer=%d FAILED: %v",
				i, j.Index, j.Justification.Index, err)
		} else {
			log.Infof("[DEBUG-REPLAY] ProcessJustification[%d] dealer=%d complainer=%d → OK",
				i, j.Index, j.Justification.Index)
		}
	}

	// Log final verifier state
	verifiers := dkgInst.Verifiers()
	for idx, v := range verifiers {
		responses := v.Responses()
		certified := v.DealCertified()
		hasDeal := v.Deal() != nil
		log.Infof("[DEBUG-REPLAY] verifiers[%d]: hasDeal=%v responses=%d certified=%v responseMap=%v",
			idx, hasDeal, len(responses), certified, formatResponses(responses))
	}

	qual := dkgInst.QUAL()
	log.Infof("[DEBUG-REPLAY] QUAL=%v ThresholdCertified=%v", qual, dkgInst.ThresholdCertified())
}

// formatResponses returns a human-readable summary of an aggregator's response map.
func formatResponses(responses map[uint32]*vss.Response) string {
	if len(responses) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(responses))
	for idx, r := range responses {
		status := "approval"
		if !r.Status {
			status = "complaint"
		}
		parts = append(parts, fmt.Sprintf("%d:%s", idx, status))
	}
	return "{" + strings.Join(parts, ", ") + "}"
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
