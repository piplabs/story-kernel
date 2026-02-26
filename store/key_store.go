package store

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/crypto"
	"github.com/piplabs/story-kernel/enclave"

	"go.dedis.ch/kyber/v4"
)

func (s *DKGStore) ed25519Path(codeCommitmentHex string, round uint32) string {
	return filepath.Join(s.keyDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, KeyEd25519File)
}

func (s *DKGStore) secp256k1Path(codeCommitmentHex string, round uint32) string {
	return filepath.Join(s.keyDir, strconv.FormatUint(uint64(round), 10), codeCommitmentHex, KeySecp256k1File)
}

func (s *DKGStore) LoadOrGenerateEd25519Key(codeCommitmentHex string, round uint32) (kyber.Scalar, kyber.Point, error) {
	var (
		edPriv kyber.Scalar
		edPub  kyber.Point
	)

	if _, err := os.Stat(s.ed25519Path(codeCommitmentHex, round)); err == nil {
		log.Info("There is the existing Ed25519 key. Load the existing one")
		edPriv, err = s.LoadSealedEd25519Key(codeCommitmentHex, round)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load the existing Ed25519 key file: %w", err)
		}

		edPub = s.suite.Point().Mul(edPriv, nil)
	} else {
		log.Info("There is no Ed25519 key file. A new Ed25519 key is generated.")
		// Generate a new keys, Ed25519 for DKG and Secp256k1 for communication
		edPriv, edPub = crypto.GenerateNewEd25519Key()

		// Seal and store the ed25519 key
		edPrivBz, err := edPriv.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal the Ed25519 private key: %w", err)
		}

		if err := s.SealAndStoreEd25519Key(codeCommitmentHex, round, edPrivBz); err != nil {
			return nil, nil, fmt.Errorf("failed to seal and store the Ed25519 private key: %w", err)
		}
	}

	return edPriv, edPub, nil
}

func (s *DKGStore) SealAndStoreEd25519Key(codeCommitmentHex string, round uint32, edPrivBz []byte) error {
	dir := filepath.Dir(s.ed25519Path(codeCommitmentHex, round))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create sealed key directory: %w", err)
	}

	if err := enclave.SealToFile(edPrivBz, s.ed25519Path(codeCommitmentHex, round)); err != nil {
		return fmt.Errorf("failed to seal ed25519 key: %w", err)
	}

	return nil
}

func (s *DKGStore) LoadSealedEd25519Key(codeCommitmentHex string, round uint32) (kyber.Scalar, error) {
	edPrivBz, err := enclave.UnsealFromFile(s.ed25519Path(codeCommitmentHex, round))
	if err != nil {
		return nil, fmt.Errorf("failed to unseal the ed25519 private key: %w", err)
	}

	return s.suite.Scalar().SetBytes(edPrivBz), nil
}

func (s *DKGStore) LoadOrGenerateSecp256k1Key(codeCommitmentHex string, round uint32) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var (
		secpPriv *ecdsa.PrivateKey
		secpPub  *ecdsa.PublicKey
		ok       bool
	)

	if _, err := os.Stat(s.secp256k1Path(codeCommitmentHex, round)); err == nil {
		log.Info("There is the existing Secp256k1 key. Load the existing one")
		secpPriv, err = s.LoadSealedSecp256k1Key(codeCommitmentHex, round)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load the existing Secp256k1 key file: %w", err)
		}

		secpPub, ok = secpPriv.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("failed to convert secp256k1 key to ecdsa public key")
		}
	} else {
		log.Info("There is no Secp256k1 key file. A new Secp256k1 key is generated.")
		// Seal and store secp256k1 key
		secpPriv, secpPub, err = crypto.GenerateNewSecp256k1Key()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate a Secp256k1 key pair: %w", err)
		}

		if err := s.SealAndStoreSecp256k1Key(codeCommitmentHex, round, secpPriv); err != nil {
			return nil, nil, fmt.Errorf("failed to seal and store the secp256k1 private key: %w", err)
		}
	}

	return secpPriv, secpPub, nil
}

func (s *DKGStore) SealAndStoreSecp256k1Key(codeCommitmentHex string, round uint32, secpPriv *ecdsa.PrivateKey) error {
	dir := filepath.Dir(s.secp256k1Path(codeCommitmentHex, round))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create sealed key directory: %w", err)
	}

	if err := enclave.SealToFile(ecrypto.FromECDSA(secpPriv), s.secp256k1Path(codeCommitmentHex, round)); err != nil {
		return fmt.Errorf("failed to seal ed25519 key: %w", err)
	}

	return nil
}

func (s *DKGStore) LoadSealedSecp256k1Key(codeCommitmentHex string, round uint32) (*ecdsa.PrivateKey, error) {
	secpPrivBz, err := enclave.UnsealFromFile(s.secp256k1Path(codeCommitmentHex, round))
	if err != nil {
		return nil, fmt.Errorf("failed to unseal the secp256k1 private key: %w", err)
	}

	secpPriv, err := ecrypto.ToECDSA(secpPrivBz)
	if err != nil {
		return nil, errors.New("failed to convert to ecdsa private key")
	}

	return secpPriv, nil
}
