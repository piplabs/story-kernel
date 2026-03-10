package service

import (
	"crypto/ecdsa"
	"math/big"
)

// zeroBytes overwrites the given byte slice with zeros.
// This is used to minimize the window during which sensitive
// key material resides in memory after it is no longer needed.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroPrivateKey overwrites an ECDSA private key's secret scalar (D)
// with zero. The caller should defer this immediately after loading
// the key.
func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key == nil || key.D == nil {
		return
	}
	key.D.SetInt64(0)
	// Also clear the internal byte representation if the big.Int
	// has allocated space.
	key.D = new(big.Int)
}
