package service

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// shamirSetup performs a Shamir (threshold)-of-(n) secret split using Kyber
// scalars and the service-layer conversion helpers. It mirrors the setup in
// the cb-mpc tdh2_test.go but exercises bytes2PrivateShare, buildTDH2PublicKey,
// and marshalPubShare so that the test validates the service integration layer.
//
// Returns the TDH2 public key, the access structure, and per-party shares.
func shamirSetup(t *testing.T, suite *edwards25519.SuiteEd25519, n, threshold int) (
	pubKey *mpc.TDH2PublicKey,
	as *mpc.AccessStructure,
	privShares map[string]*mpc.TDH2PrivateShare,
	pubShares map[string][]byte,
	pids map[string]int,
) {
	t.Helper()

	// Sample the master secret.
	x := suite.Scalar().Pick(suite.RandomStream())

	// Polynomial coefficients: f(z) = x + a1*z + ... + a_{t-1}*z^{t-1}
	coeffs := make([]kyber.Scalar, threshold)
	coeffs[0] = x
	for i := 1; i < threshold; i++ {
		coeffs[i] = suite.Scalar().Pick(suite.RandomStream())
	}

	// evalAt evaluates the polynomial at the given PID using Kyber scalar arithmetic.
	evalAt := func(pid int) kyber.Scalar {
		z := suite.Scalar().SetInt64(int64(pid))
		acc := suite.Scalar().Zero()
		zPow := suite.Scalar().One()
		for _, c := range coeffs {
			term := suite.Scalar().Mul(c, zPow)
			acc.Add(acc, term)
			zPow.Set(suite.Scalar().Mul(zPow, z))
		}
		return acc
	}

	// Compute global public key via marshalPubShare (which uses cb-mpc internally),
	// then strip the 2-byte cb-mpc prefix to get the raw 32-byte DKG pub key
	// expected by buildTDH2PublicKey.
	globalPubBytes, err := marshalPubShare(x)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(globalPubBytes), 2, "marshalPubShare must return at least 2 prefix bytes")
	pubKey, err = buildTDH2PublicKey(globalPubBytes[2:])
	require.NoError(t, err)
	t.Cleanup(pubKey.Free)

	// Build party names and explicit PIDs (1-indexed, matching the DKG convention).
	pnames := make([]string, n)
	explicitPIDs := make([]int, n)
	for i := range n {
		pnames[i] = fmt.Sprintf("party-%d", i+1)
		explicitPIDs[i] = i + 1
	}

	// Build the access structure.
	kids := make([]*mpc.AccessNode, n)
	for i, name := range pnames {
		pid := explicitPIDs[i]
		kids[i] = &mpc.AccessNode{Name: name, Kind: mpc.KindLeaf, ExplicitPID: &pid}
	}
	cv, err := curve.NewEd25519()
	require.NoError(t, err)
	t.Cleanup(cv.Free)
	as = &mpc.AccessStructure{Root: mpc.Threshold("", threshold, kids...), Curve: cv}

	// Compute per-party private and public shares.
	privShares = make(map[string]*mpc.TDH2PrivateShare, n)
	pubShares = make(map[string][]byte, n)
	pids = make(map[string]int, n)
	for i, name := range pnames {
		xi := evalAt(explicitPIDs[i])

		priv, err := bytes2PrivateShare(xi)
		require.NoError(t, err)
		privShares[name] = priv

		pub, err := marshalPubShare(xi)
		require.NoError(t, err)
		pubShares[name] = pub

		pids[name] = explicitPIDs[i]
	}

	return pubKey, as, privShares, pubShares, pids
}

// TestTDH2ServiceEndToEnd verifies the full TDH2 workflow through the service
// conversion helpers: Shamir split → encrypt → per-party partial decrypt →
// combine to recover plaintext, using all n parties.
func TestTDH2ServiceEndToEnd(t *testing.T) {
	const (
		n         = 5
		threshold = 3
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, as, privShares, pubShares, pids := shamirSetup(t, suite, n, threshold)

	plaintext := []byte("end-to-end tdh2 service test")
	label := []byte("test-label")

	ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
	require.NoError(t, err)
	require.NotEmpty(t, ct.Bytes)

	require.NoError(t, ct.Verify(pubKey, label))

	partials := make(map[string]*mpc.TDH2PartialDecryption, n)
	for name, priv := range privShares {
		pd, err := mpc.TDH2PartialDecrypt(pids[name], priv, pubKey, ct, label)
		require.NoError(t, err, "partial decrypt failed for %s", name)
		partials[name] = pd
	}

	recovered, err := mpc.TDH2Combine(as, pubKey, pubShares, ct, label, partials)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

// TestTDH2ServiceThresholdQuorum verifies that exactly threshold parties suffice.
func TestTDH2ServiceThresholdQuorum(t *testing.T) {
	const (
		n         = 5
		threshold = 3
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, as, privShares, pubShares, pids := shamirSetup(t, suite, n, threshold)

	plaintext := []byte("quorum service decryption test")
	label := []byte("quorum-label")

	ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
	require.NoError(t, err)

	// Only the first threshold parties participate.
	partials := make(map[string]*mpc.TDH2PartialDecryption, threshold)
	count := 0
	for name, priv := range privShares {
		if count >= threshold {
			break
		}
		pd, err := mpc.TDH2PartialDecrypt(pids[name], priv, pubKey, ct, label)
		require.NoError(t, err)
		partials[name] = pd
		count++
	}

	recovered, err := mpc.TDH2Combine(as, pubKey, pubShares, ct, label, partials)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

// TestTDH2ServiceWithRequesterEncryption verifies the full workflow including
// the requester encryption layer used by PartialDecryptTDH2: each partial
// decryption is encrypted for the requester, then decrypted and combined.
func TestTDH2ServiceWithRequesterEncryption(t *testing.T) {
	const (
		n         = 5
		threshold = 3
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, as, privShares, pubShares, pids := shamirSetup(t, suite, n, threshold)

	plaintext := []byte("requester encryption e2e test")
	label := []byte("requester-label")

	ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
	require.NoError(t, err)

	// Requester generates an ephemeral secp256k1 key pair.
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Each party produces an encrypted partial decryption (as PartialDecryptTDH2 does).
	type encryptedPartial struct {
		encrypted []byte
		ephPub    []byte
	}
	encryptedPartials := make(map[string]encryptedPartial, n)
	for name, priv := range privShares {
		pd, err := mpc.TDH2PartialDecrypt(pids[name], priv, pubKey, ct, label)
		require.NoError(t, err)

		encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, pd.Bytes)
		require.NoError(t, err)

		encryptedPartials[name] = encryptedPartial{encrypted: encrypted, ephPub: ephPub}
	}

	// Requester decrypts each partial and combines.
	partials := make(map[string]*mpc.TDH2PartialDecryption, n)
	for name, ep := range encryptedPartials {
		decrypted, err := decryptPartialFromRequester(requesterPriv, ep.ephPub, ep.encrypted)
		require.NoError(t, err)
		partials[name] = &mpc.TDH2PartialDecryption{Bytes: decrypted}
	}

	recovered, err := mpc.TDH2Combine(as, pubKey, pubShares, ct, label, partials)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

// TestTDH2VerifyRejectsInvalidCiphertext verifies that TDH2Verify returns a
// non-nil error for corrupted or garbage ciphertext, confirming that the
// enforcement gate in PartialDecryptTDH2 will block invalid inputs.
func TestTDH2VerifyRejectsInvalidCiphertext(t *testing.T) {
	const (
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, _, _, _, _ := shamirSetup(t, suite, n, threshold)

	label := []byte("verify-reject-label")

	t.Run("garbage ciphertext bytes", func(t *testing.T) {
		garbageCT := make([]byte, 256)
		for i := range garbageCT {
			garbageCT[i] = byte(i)
		}

		err := mpc.TDH2Verify(pubKey, garbageCT, label)
		require.Error(t, err, "TDH2Verify must reject garbage ciphertext")
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		err := mpc.TDH2Verify(pubKey, []byte{}, label)
		require.Error(t, err, "TDH2Verify must reject empty ciphertext")
	})

	t.Run("valid ciphertext passes", func(t *testing.T) {
		plaintext := []byte("valid-data")
		ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
		require.NoError(t, err)

		err = mpc.TDH2Verify(pubKey, ct.Bytes, label)
		require.NoError(t, err, "TDH2Verify must accept valid ciphertext")
	})

	t.Run("corrupted valid ciphertext", func(t *testing.T) {
		plaintext := []byte("corrupt-me")
		ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
		require.NoError(t, err)

		// Corrupt a byte in the ciphertext
		corrupted := make([]byte, len(ct.Bytes))
		copy(corrupted, ct.Bytes)
		if len(corrupted) > 10 {
			corrupted[10] ^= 0xFF
		}

		err = mpc.TDH2Verify(pubKey, corrupted, label)
		require.Error(t, err, "TDH2Verify must reject corrupted ciphertext")
	})

	t.Run("wrong label", func(t *testing.T) {
		plaintext := []byte("wrong-label-test")
		ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
		require.NoError(t, err)

		wrongLabel := []byte("different-label")
		err = mpc.TDH2Verify(pubKey, ct.Bytes, wrongLabel)
		require.Error(t, err, "TDH2Verify must reject ciphertext verified with wrong label")
	})
}
