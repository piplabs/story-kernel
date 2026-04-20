package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/enclave"

	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

const (
	KeyEd25519File   = "ed25519_priv.sealed"
	KeySecp256k1File = "secp256k1_priv.sealed"

	DKGStateFile      = "state.json"
	PrivateCoeffsFile = "private_coeffs.sealed"
)

// Sealer abstracts seal/unseal operations so tests can inject a plaintext
// implementation that does not require SGX hardware.
type Sealer interface {
	SealToFile(data []byte, path string) error
	UnsealFromFile(path string) ([]byte, error)
}

// enclaveSealer delegates to the real SGX enclave seal/unseal functions.
type enclaveSealer struct{}

func (enclaveSealer) SealToFile(data []byte, path string) error {
	return enclave.SealToFile(data, path)
}

func (enclaveSealer) UnsealFromFile(path string) ([]byte, error) {
	return enclave.UnsealFromFile(path)
}

type DKGStore struct {
	suite  *edwards25519.SuiteEd25519
	sealer Sealer

	keyDir   string
	stateDir string
}

// NewDKGStore creates a DKGStore that uses the real SGX enclave sealer.
func NewDKGStore(keyDir, stateDir string, suite *edwards25519.SuiteEd25519) *DKGStore {
	return &DKGStore{
		suite:    suite,
		sealer:   enclaveSealer{},
		keyDir:   keyDir,
		stateDir: stateDir,
	}
}

// NewDKGStoreWithSealer creates a DKGStore with a custom Sealer implementation.
// This is intended for testing with a plaintext sealer that does not require SGX.
func NewDKGStoreWithSealer(keyDir, stateDir string, suite *edwards25519.SuiteEd25519, sealer Sealer) *DKGStore {
	return &DKGStore{
		suite:    suite,
		sealer:   sealer,
		keyDir:   keyDir,
		stateDir: stateDir,
	}
}

// SealAndStoreDistKeyShare serializes and seals the DistKeyShare to a file.
func (s *DKGStore) SealAndStoreDistKeyShare(share *dkg.DistKeyShare, codeCommitmentHex string, round uint32) error {
	distKeyShareDir := filepath.Join(s.stateDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex)
	if err := os.MkdirAll(distKeyShareDir, 0o700); err != nil {
		return fmt.Errorf("failed to create sealed DistKeyShare directory: %w", err)
	}

	path := filepath.Join(distKeyShareDir, config.DistKeyShareFile)
	shareBz, err := MarshalDistKeyShare(share)
	if err != nil {
		return fmt.Errorf("failed to marshal the DistKeyShare: %w", err)
	}

	if err := s.sealer.SealToFile(shareBz, path); err != nil {
		return fmt.Errorf("failed to seal and store DistKeyShare to file: %w", err)
	}

	return nil
}

// LoadDistKeyShare loads and unseals a DistKeyShare from a file.
func (s *DKGStore) LoadDistKeyShare(codeCommitmentHex string, round uint32) (*dkg.DistKeyShare, error) {
	path := filepath.Join(s.stateDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, config.DistKeyShareFile)
	sealed, err := s.sealer.UnsealFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal DistKeyShare: %w", err)
	}

	share, err := UnmarshalDistKeyShare(sealed, s.suite)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal the loaded DistKeyShare data: %w", err)
	}

	return share, nil
}

// HasAnyDistKeyShare checks whether any dist_key_share.sealed file exists in
// this store's state directory.
func (s *DKGStore) HasAnyDistKeyShare() (bool, error) {
	return HasAnyDistKeyShareInDir(s.stateDir)
}

// HasAnyDistKeyShareInDir walks the given DKG state directory to check whether
// any dist_key_share.sealed file exists under any round/codeCommitment
// subdirectory. The directory layout is:
//
//	{stateDir}/{round}/{codeCommitment}/dist_key_share.sealed
//
// After DKG registration, the light client must resume from sealed DB rather
// than config.toml to preserve chain identity continuity. If the directory does
// not exist, it returns (false, nil).
func HasAnyDistKeyShareInDir(stateDir string) (bool, error) {
	if _, err := os.Stat(stateDir); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to stat DKG state dir: %w", err)
	}

	roundEntries, err := os.ReadDir(stateDir)
	if err != nil {
		return false, fmt.Errorf("failed to read DKG state dir: %w", err)
	}

	for _, roundEntry := range roundEntries {
		if !roundEntry.IsDir() {
			continue
		}

		roundPath := filepath.Join(stateDir, roundEntry.Name())
		commitEntries, err := os.ReadDir(roundPath)
		if err != nil {
			// Skip unreadable round directories rather than failing hard.
			continue
		}

		for _, commitEntry := range commitEntries {
			if !commitEntry.IsDir() {
				continue
			}

			sharePath := filepath.Join(roundPath, commitEntry.Name(), config.DistKeyShareFile)
			if _, err := os.Stat(sharePath); err == nil {
				return true, nil
			}
		}
	}

	return false, nil
}
