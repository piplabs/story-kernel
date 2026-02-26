package crypto

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func GenerateNewSecp256k1Key() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	pubKey, ok := privKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("failed to convert to ecdsa public key")
	}

	return privKey, pubKey, nil
}
