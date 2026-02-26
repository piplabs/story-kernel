package store

import (
	"bytes"
	"encoding/gob"
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

	DKGStateFile     = "state.json"
	DKGStateLockFile = "state.lock"
)

type DKGStore struct {
	suite *edwards25519.SuiteEd25519

	keyDir   string
	stateDir string
}

func NewDKGStore(keyDir, stateDir string, suite *edwards25519.SuiteEd25519) *DKGStore {
	return &DKGStore{
		suite:    suite,
		keyDir:   keyDir,
		stateDir: stateDir,
	}
}

func SealAndStoreDKGState(dkg *dkg.DistKeyGenerator, dir, codeCommitmentHex string, round uint32) error {
	path := filepath.Join(dir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, config.DKGFile)

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)

	if err := enc.Encode(dkg); err != nil {
		return fmt.Errorf("failed to encode DKG state: %w", err)
	}

	if err := enclave.SealToFile(buf.Bytes(), path); err != nil {
		return fmt.Errorf("failed to seal DKG state: %w", err)
	}

	return nil
}

// SealAndStoreDistKeyShare serializes and seals the DistKeyShare to a file.
func SealAndStoreDistKeyShare(share *dkg.DistKeyShare, dir, codeCommitmentHex string, round uint32) error {
	distKeyShareDir := filepath.Join(dir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex)
	if err := os.MkdirAll(distKeyShareDir, 0o700); err != nil {
		return fmt.Errorf("failed to create sealed DistKeyShare directory: %w", err)
	}

	path := filepath.Join(distKeyShareDir, config.DistKeyShareFile)
	shareBz, err := MarshalDistKeyShare(share)
	if err != nil {
		return fmt.Errorf("failed to marshal the DistKeyShare: %w", err)
	}

	if err := enclave.SealToFile(shareBz, path); err != nil {
		return fmt.Errorf("failed to seal and store DistKeyShare to file: %w", err)
	}

	return nil
}

// LoadDistKeyShare loads and unseals a DistKeyShare from a file.
func LoadDistKeyShare(dir, codeCommitmentHex string, round uint32) (*dkg.DistKeyShare, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	path := filepath.Join(dir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, config.DistKeyShareFile)
	sealed, err := enclave.UnsealFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal DistKeyShare: %w", err)
	}

	share, err := UnmarshalDistKeyShare(sealed, suite)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal the loaded DistKeyShare data: %w", err)
	}

	return share, nil
}
