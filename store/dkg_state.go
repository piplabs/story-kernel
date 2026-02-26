package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gofrs/flock"
	"github.com/pkg/errors"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

type DKGState struct {
	PubKeys      []kyber.Point
	Threshold    uint32
	Deals        []dkg.Deal
	Responses    []dkg.Response
	PublicCoeffs []kyber.Point

	// FromRound indicates the original round from which this DKG state was derived.
	// It is mainly used for resharing: when a new round is created based on the
	// public information (pub keys, threshold, public coefficients) of a previous
	// committee, the previous round number is stored here for recovery.
	// For initial round (round == 1), it is set to be 0
	FromRound uint32
}

type dkgStateDisk struct {
	PubKeysBase64 []string       `json:"pub_keys_base_64"`
	Threshold     uint32         `json:"threshold"`
	Deals         []dkg.Deal     `json:"deals"`
	Responses     []dkg.Response `json:"responses"`
}

func (s *DKGStore) statePath(codeCommitmentHex string, round uint32) string {
	return filepath.Join(s.stateDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, DKGStateFile)
}

func (s *DKGStore) lockPath(codeCommitmentHex string, round uint32) string {
	return filepath.Join(s.stateDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, DKGStateLockFile)
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
	lock := flock.New(s.lockPath(codeCommitmentHex, round))

	if err := lock.Lock(); err != nil {
		return errors.Wrapf(err, "failed to acquire write lock for code_commitment=%s round=%d", codeCommitmentHex, round)
	}
	defer func() { _ = lock.Unlock() }()

	st, err := s.loadState(path)
	if err != nil {
		return errors.Wrapf(err, "failed to load state for code_commitment=%s round=%d", codeCommitmentHex, round)
	}

	update(st)

	return s.saveState(st, path)
}

func (s *DKGStore) LoadDKGState(codeCommitmentHex string, round uint32) (*DKGState, error) {
	path := s.statePath(codeCommitmentHex, round)
	lock := flock.New(s.lockPath(codeCommitmentHex, round))

	if err := lock.RLock(); err != nil {
		return nil, errors.Wrapf(err, "failed to acquire read lock for code_commitment=%s round=%d", codeCommitmentHex, round)
	}
	defer func() { _ = lock.Unlock() }()

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
	lock := flock.New(s.lockPath(codeCommitmentHex, round))

	if err := lock.Lock(); err != nil {
		return errors.Wrapf(err, "failed to acquire write lock for code_commitment=%s round=%d", codeCommitmentHex, round)
	}
	defer func() { _ = lock.Unlock() }()

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

func (s *DKGStore) toDisk(st *DKGState) (*dkgStateDisk, error) {
	d := &dkgStateDisk{
		Threshold:     st.Threshold,
		Deals:         st.Deals,
		Responses:     st.Responses,
		PubKeysBase64: make([]string, len(st.PubKeys)),
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
	st := &DKGState{
		Threshold: d.Threshold,
		Deals:     d.Deals,
		Responses: d.Responses,
		PubKeys:   make([]kyber.Point, len(d.PubKeysBase64)),
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
