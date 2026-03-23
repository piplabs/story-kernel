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

// Sealer abstracts file-level seal/unseal operations so that production code
// uses SGX sealing (enclave.SealToFile/UnsealFromFile) while tests can inject
// a plaintext implementation.
type Sealer interface {
	SealToFile(data []byte, path string) error
	UnsealFromFile(path string) ([]byte, error)
}

// enclaveSealer is the production sealer that uses SGX enclave sealing.
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

func NewDKGStore(keyDir, stateDir string, suite *edwards25519.SuiteEd25519) *DKGStore {
	return &DKGStore{
		suite:    suite,
		sealer:   enclaveSealer{},
		keyDir:   keyDir,
		stateDir: stateDir,
	}
}

// NewDKGStoreWithSealer creates a DKGStore with a custom sealer (for testing).
func NewDKGStoreWithSealer(keyDir, stateDir string, suite *edwards25519.SuiteEd25519, sealer Sealer) *DKGStore {
	return &DKGStore{
		suite:    suite,
		sealer:   sealer,
		keyDir:   keyDir,
		stateDir: stateDir,
	}
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
