package service

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProcessJustification takes valid justifications from the CL and calls kyber's
// DistKeyGenerator.ProcessJustification() for each to restore the DKG state for
// the originally-complained deals. This is only called when the CL has already
// verified each justification via Pedersen VSS verification.
func (s *DKGServer) ProcessJustification(_ context.Context, req *pb.ProcessJustificationRequest) (*pb.ProcessJustificationResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessJustificationRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request")
	}

	// Validate code commitment
	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("failed to validate code commitment: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "failed to validate code commitment")
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	// Bounds-check references for the per-item loop:
	//   dealerCount    — upper bound for outer Justification.Index (the dealer).
	//   recipientCount — upper bound for inner VssJustification.Index
	//                    (the recipient of the original deal).
	// Non-resharing rounds have a single committee acting as both. In
	// resharing, dealers live in the OLD committee and recipients live
	// in the NEW committee.
	var dealerCount, recipientCount int

	var distKeyGens []*dkg.DistKeyGenerator
	if !req.GetIsResharing() {
		dealerCount = len(rc.SortedPubKeys)
		recipientCount = len(rc.SortedPubKeys)

		distKeyGen, err := s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild initial distributed key generator: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial distributed key generator")
		}
		distKeyGens = append(distKeyGens, distKeyGen)
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			log.Errorf("failed to get the latest active round of DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to get the latest active round of DKG")
		}
		// Defence in depth against a future regression that returns
		// (nil, nil) on an uninitialised state.
		if latest == nil || latest.GetTotal() == 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"resharing requires an active prior DKG network")
		}

		dealerCount = int(latest.GetTotal())   // OLD committee
		recipientCount = len(rc.SortedPubKeys) // NEW committee

		prevDistKeyGen, err := s.GetResharingPrevDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys, latest)
		if err != nil {
			log.Infof("failed to load or rebuild the previous distributed key generator for resharing, skip processing justifications for the previous distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, prevDistKeyGen)
		}

		nextDistKeyGen, err := s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the next distributed key generator for resharing, skip processing justifications for the next distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, nextDistKeyGen)
		}
	}

	// Fail loudly if no DistKeyGenerator is available (see ProcessResponses for
	// the same guard — otherwise the per-item loop silently succeeds).
	if len(distKeyGens) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no DistKeyGenerator available for this round (node not a member of the required committee(s))")
	}

	// Process each justification. A justification is considered rejected iff
	// proto conversion fails, the dealer/recipient index is out of bounds, OR
	// every configured DistKeyGenerator rejects it with a non-idempotent error.
	// If every generator returns an idempotent "already processed" error the
	// justification is silently skipped (NOT added to rejected_justifications).
	var (
		justs    []dkg.Justification
		rejected []*pb.Justification
	)

	// Serialize the shared DistKeyGenerator mutation with the other DKG-mutating
	// RPCs for this round (see dkgMutationMu). Persist runs after the loop under
	// its own store lock, so only the kyber mutation needs covering here. The
	// loop runs in a closure so a panic still releases the lock via defer,
	// without widening the critical section to the store IO below.
	mu := s.getDKGMutationMu(req.GetRound())
	func() {
		mu.Lock()
		defer mu.Unlock()

		for _, j := range req.GetJustifications() {
			justification, err := types.ConvertToJustification(j)
			if err != nil {
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
				}).Errorf("failed to convert justification from proto: %v", err)

				rejected = append(rejected, j)

				continue
			}

			// Defence in depth: bounds-check both the dealer and the recipient
			// index before kyber. In resharing the dealer is an old-committee
			// member (range [0, dealerCount)) and the recipient is a new-committee
			// member (range [0, recipientCount)).
			if int(justification.Index) >= dealerCount ||
				int(j.GetVssJustification().GetIndex()) >= recipientCount {
				rejected = append(rejected, j)

				continue
			}

			// applied:          at least one DistKeyGenerator successfully
			//                   absorbed this justification on THIS call. Only
			//                   then is it safe to persist for replay.
			// alreadyProcessed: at least one DistKeyGenerator reported the
			//                   justification was absorbed on a PRIOR call
			//                   (idempotent re-submission). Silently skip — do
			//                   not reject, do not persist. Persisting a
			//                   duplicate would cause replayMessages (which
			//                   does NOT suppress duplicate justification
			//                   errors, unlike responses) to fail fatally on
			//                   restart.
			// Reject only when EVERY generator returned a real (non-idempotent)
			// error.
			applied := false
			alreadyProcessed := false
			for _, distKeyGen := range distKeyGens {
				if err := distKeyGen.ProcessJustification(justification); err != nil {
					log.WithFields(log.Fields{
						"round":           req.GetRound(),
						"code_commitment": codeCommitmentHex,
						"dealer_index":    justification.Index,
					}).Errorf("failed to process justification: %v", err)

					if isAlreadyProcessedErr(err) {
						alreadyProcessed = true
					}

					continue
				}
				applied = true
			}

			if !applied && !alreadyProcessed {
				rejected = append(rejected, j)

				continue
			}

			if !applied {
				// Idempotent re-submission only — do not persist. Logging at
				// debug to mirror the dealing handler's silent-skip semantics.
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
					"dealer_index":    justification.Index,
				}).Debug("justification already stored on cached generator; skipping silently")

				continue
			}

			justs = append(justs, *justification)

			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
				"dealer_index":    justification.Index,
			}).Info("Justification processed successfully, DKG state restored for the deal")
		}
	}()

	// Persist successfully processed justifications for recovery replay
	if len(justs) > 0 {
		if err := s.DKGStore.AddJustifications(codeCommitmentHex, req.GetRound(), justs); err != nil {
			log.Errorf("failed to add justifications to the DKG state: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to add justifications to the DKG state")
		}
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"processed":       len(justs),
		"rejected":        len(rejected),
	}).Info("Processed justifications")

	return &pb.ProcessJustificationResponse{
		RejectedJustifications: rejected,
	}, nil
}

func validateProcessJustificationRequest(req *pb.ProcessJustificationRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	if len(req.GetJustifications()) == 0 {
		return errors.New("justifications are required but missing")
	}

	return nil
}
