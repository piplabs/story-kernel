package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/pkg/errors"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// stateMu protects concurrent DKG state file access within this process.
// Replaces file-based flock which is not supported in SGX/Gramine (ENOSYS).
var stateMu sync.Mutex

type DKGState struct {
	PubKeys        []kyber.Point
	Threshold      uint32
	Deals          []dkg.Deal
	Responses      []dkg.Response
	Justifications []dkg.Justification
	PublicCoeffs   []kyber.Point

	// FromRound indicates the original round from which this DKG state was derived.
	// It is mainly used for resharing: when a new round is created based on the
	// public information (pub keys, threshold, public coefficients) of a previous
	// committee, the previous round number is stored here for recovery.
	// For initial round (round == 1), it is set to be 0
	FromRound uint32
}

type dkgStateDisk struct {
	PubKeysBase64  []string            `json:"pub_keys_base_64"`
	Threshold      uint32              `json:"threshold"`
	Deals          []dkg.Deal          `json:"deals"`
	Responses      []dkg.Response      `json:"responses"`
	Justifications []justificationDisk `json:"justifications,omitempty"`
	FromRound      uint32              `json:"from_round,omitempty"`
}

// justificationDisk is the JSON-serializable representation of dkg.Justification.
// dkg.Justification contains kyber.Scalar and kyber.Point interfaces which
// cannot be directly JSON-serialized, so we store them as raw byte slices.
type justificationDisk struct {
	Index     uint32                `json:"index"`
	SessionID []byte                `json:"session_id"`
	VSSIndex  uint32                `json:"vss_index"`
	Deal      justificationDealDisk `json:"deal"`
	Signature []byte                `json:"signature"`
}

type justificationDealDisk struct {
	SessionID   []byte   `json:"session_id"`
	SecShareI   int      `json:"sec_share_i"`
	SecShareV   []byte   `json:"sec_share_v"`
	T           uint32   `json:"t"`
	Commitments [][]byte `json:"commitments"`
}

func (s *DKGStore) statePath(codeCommitmentHex string, round uint32) string {
	return filepath.Join(s.stateDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, DKGStateFile)
}

func (s *DKGStore) loadState(path string) (*DKGState, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &DKGState{}, nil
		}

		return nil, err
	}

	var disk dkgStateDisk
	if err := json.Unmarshal(bz, &disk); err != nil {
		return nil, err
	}

	return s.fromDisk(&disk)
}

func (s *DKGStore) saveState(st *DKGState, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	disk, err := s.toDisk(st)
	if err != nil {
		return err
	}

	bz, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, bz, 0o600)
}

func (s *DKGStore) updateState(codeCommitmentHex string, round uint32, update func(st *DKGState)) error {
	path := s.statePath(codeCommitmentHex, round)

	stateMu.Lock()
	defer stateMu.Unlock()

	st, err := s.loadState(path)
	if err != nil {
		return errors.Wrapf(err, "failed to load state for code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	update(st)

	return s.saveState(st, path)
}

func (s *DKGStore) LoadDKGState(codeCommitmentHex string, round uint32) (*DKGState, error) {
	path := s.statePath(codeCommitmentHex, round)

	stateMu.Lock()
	defer stateMu.Unlock()

	return s.loadState(path)
}

func (s *DKGStore) HasDKGState(codeCommitmentHex string, round uint32) (bool, error) {
	st, err := s.LoadDKGState(codeCommitmentHex, round)
	if err != nil {
		return false, errors.Wrapf(err, "failed to load DKG state for code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	if st == nil {
		return false, nil
	}

	if st.Threshold == 0 {
		return false, nil
	}
	if len(st.PubKeys) == 0 {
		return false, nil
	}

	return true, nil
}

func (s *DKGStore) SaveDKGState(st *DKGState, codeCommitmentHex string, round uint32) error {
	path := s.statePath(codeCommitmentHex, round)

	stateMu.Lock()
	defer stateMu.Unlock()

	return s.saveState(st, path)
}

func (s *DKGStore) SetNextDKGState(
	codeCommitmentHex string,
	fromRound, toRound, threshold uint32,
	pubs []kyber.Point,
) error {
	return s.updateState(codeCommitmentHex, toRound, func(st *DKGState) {
		st.Threshold = threshold
		st.PubKeys = pubs
		st.FromRound = fromRound
	})
}

func (s *DKGStore) SetPrevDKGState(
	codeCommitmentHex string,
	round, threshold uint32,
	pubs []kyber.Point,
	publicCoeffs []kyber.Point,
) error {
	return s.updateState(codeCommitmentHex, round, func(st *DKGState) {
		isEmpty := len(st.PubKeys) == 0 && st.Threshold == 0

		if isEmpty {
			st.Threshold = threshold
			st.PubKeys = pubs
		}
		st.PublicCoeffs = publicCoeffs
	})
}

func (s *DKGStore) SetPublicCoeffs(
	codeCommitmentHex string,
	round uint32,
	publicCoeffs []kyber.Point,
) error {
	return s.updateState(codeCommitmentHex, round, func(st *DKGState) {
		st.PublicCoeffs = publicCoeffs
	})
}

func (s *DKGStore) AddDeals(codeCommitmentHex string, round uint32, deals []dkg.Deal) error {
	return s.updateState(codeCommitmentHex, round, func(st *DKGState) {
		st.Deals = append(st.Deals, deals...)
	})
}

func (s *DKGStore) AddResponses(codeCommitmentHex string, round uint32, resps []dkg.Response) error {
	return s.updateState(codeCommitmentHex, round, func(st *DKGState) {
		st.Responses = append(st.Responses, resps...)
	})
}

func (s *DKGStore) AddJustifications(codeCommitmentHex string, round uint32, justs []dkg.Justification) error {
	return s.updateState(codeCommitmentHex, round, func(st *DKGState) {
		st.Justifications = append(st.Justifications, justs...)
	})
}

func (s *DKGStore) toDisk(st *DKGState) (*dkgStateDisk, error) {
	justDisk, err := justificationsToDisk(st.Justifications)
	if err != nil {
		return nil, errors.Wrap(err, "marshal justifications")
	}

	d := &dkgStateDisk{
		Threshold:      st.Threshold,
		Deals:          st.Deals,
		Responses:      st.Responses,
		Justifications: justDisk,
		FromRound:      st.FromRound,
		PubKeysBase64:  make([]string, len(st.PubKeys)),
	}

	for i, p := range st.PubKeys {
		enc, err := s.encodePubKey(p)
		if err != nil {
			return nil, err
		}
		d.PubKeysBase64[i] = enc
	}

	return d, nil
}

func (s *DKGStore) fromDisk(d *dkgStateDisk) (*DKGState, error) {
	justs, err := justificationsFromDisk(s.suite, d.Justifications)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal justifications")
	}

	st := &DKGState{
		Threshold:      d.Threshold,
		Deals:          d.Deals,
		Responses:      d.Responses,
		Justifications: justs,
		FromRound:      d.FromRound,
		PubKeys:        make([]kyber.Point, len(d.PubKeysBase64)),
	}

	for i, enc := range d.PubKeysBase64 {
		p, err := s.decodePubKey(enc)
		if err != nil {
			return nil, err
		}
		st.PubKeys[i] = p
	}

	return st, nil
}

// justificationsToDisk converts kyber justifications to their serializable form.
func justificationsToDisk(justs []dkg.Justification) ([]justificationDisk, error) {
	if len(justs) == 0 {
		return nil, nil
	}

	result := make([]justificationDisk, len(justs))
	for i, j := range justs {
		if j.Justification == nil || j.Justification.Deal == nil || j.Justification.Deal.SecShare == nil {
			return nil, fmt.Errorf("justification[%d] has nil inner fields", i)
		}

		scalarBz, err := j.Justification.Deal.SecShare.V.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal justification[%d] sec share scalar: %w", i, err)
		}

		commitBzs := make([][]byte, len(j.Justification.Deal.Commitments))
		for ci, c := range j.Justification.Deal.Commitments {
			bz, err := c.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("marshal justification[%d] commitment[%d]: %w", i, ci, err)
			}
			commitBzs[ci] = bz
		}

		result[i] = justificationDisk{
			Index:     j.Index,
			SessionID: j.Justification.SessionID,
			VSSIndex:  j.Justification.Index,
			Deal: justificationDealDisk{
				SessionID:   j.Justification.Deal.SessionID,
				SecShareI:   j.Justification.Deal.SecShare.I,
				SecShareV:   scalarBz,
				T:           j.Justification.Deal.T,
				Commitments: commitBzs,
			},
			Signature: j.Justification.Signature,
		}
	}

	return result, nil
}

// justificationsFromDisk reconstructs kyber justifications from their serialized form.
func justificationsFromDisk(suite kyber.Group, disks []justificationDisk) ([]dkg.Justification, error) {
	if len(disks) == 0 {
		return nil, nil
	}

	result := make([]dkg.Justification, len(disks))
	for i, d := range disks {
		scalar := suite.Scalar()
		if err := scalar.UnmarshalBinary(d.Deal.SecShareV); err != nil {
			return nil, fmt.Errorf("unmarshal justification[%d] sec share scalar: %w", i, err)
		}

		commits := make([]kyber.Point, len(d.Deal.Commitments))
		for ci, cb := range d.Deal.Commitments {
			p := suite.Point()
			if err := p.UnmarshalBinary(cb); err != nil {
				return nil, fmt.Errorf("unmarshal justification[%d] commitment[%d]: %w", i, ci, err)
			}
			commits[ci] = p
		}

		result[i] = dkg.Justification{
			Index: d.Index,
			Justification: &vss.Justification{
				SessionID: d.SessionID,
				Index:     d.VSSIndex,
				Deal: &vss.Deal{
					SessionID: d.Deal.SessionID,
					SecShare: &share.PriShare{
						I: d.Deal.SecShareI,
						V: scalar,
					},
					T:           d.Deal.T,
					Commitments: commits,
				},
				Signature: d.Signature,
			},
		}
	}

	return result, nil
}
