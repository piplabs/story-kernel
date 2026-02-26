package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/crypto"
)

type Msg struct {
	CodeCommitment   [32]byte
	Round            uint32
	ParticipantsRoot [32]byte
	GlobalPubKey     []byte
	PublicCoeffsBz   [][]byte
	PubKeyShare      []byte
}

// _verifyFinalizationSignature in DKG.sol.
func verifyFinalizationSignature(commPubKey []byte, round uint32, codeCommitment [32]byte, participantsRoot [32]byte, globalPubKey []byte, publicCoeffs [][]byte, pubKeyShare []byte, signature []byte) bool {
	// Solidity: keccak256(abi.encodePacked(codeCommitment, round, participantsRoot, globalPubKey, publicCoeffs))
	encoded := append([]byte{}, codeCommitment[:]...)
	encoded = append(encoded, uint32ToBytes(round)...)
	encoded = append(encoded, participantsRoot[:]...)
	encoded = append(encoded, globalPubKey...)

	for _, coeff := range publicCoeffs {
		if len(coeff) == 0 {
			panic("empty coefficient")
		}
		encoded = append(encoded, coeff...)
	}

	encoded = append(encoded, pubKeyShare...)

	msgHash := ecrypto.Keccak256(encoded)

	// Solidity: MessageHashUtils.toEthSignedMessageHash(msgHash)
	ethMsgHash := toEthSignedMessageHash(msgHash)

	// Solidity: signature recovery
	pubKey, err := ecrypto.SigToPub(ethMsgHash, signature)
	if err != nil {
		return false
	}

	recoveredAddr := ecrypto.PubkeyToAddress(*pubKey)

	// Solidity: address(uint160(uint256(keccak256(commPubKey))))
	commAddr := ecrypto.PubkeyToAddress(*mustPubKeyFromBytes(commPubKey))

	return bytes.Equal(recoveredAddr.Bytes(), commAddr.Bytes())
}

func mustPubKeyFromBytes(pubKeyBytes []byte) *ecdsa.PublicKey {
	pubKey, err := ecrypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		panic(err)
	}

	return pubKey
}

func TestSignatureFlow(t *testing.T) {
	privKey, pubKey, err := crypto.GenerateNewSecp256k1Key()
	require.NoError(t, err)

	pubBytes := ecrypto.FromECDSAPub(pubKey)

	var codeCommitment [32]byte
	copy(codeCommitment[:], []byte("dummy-code-commitment"))

	msg := Msg{
		CodeCommitment:   codeCommitment,
		Round:            42,
		ParticipantsRoot: [32]byte{1, 2, 3},
		GlobalPubKey:     []byte("dummy-global-pubkey"),
		PublicCoeffsBz: [][]byte{
			[]byte("point-coeff-01"),
			[]byte("point-coeff-02"),
			[]byte("point-coeff-03"),
		},
		PubKeyShare: []byte("dummpy-dist-pubkey"),
	}

	ethMsgHash, err := hashFinalizeDKGResponse(msg.CodeCommitment[:], msg.Round, msg.ParticipantsRoot, msg.GlobalPubKey, msg.PublicCoeffsBz, msg.PubKeyShare)
	require.NoError(t, err)

	sig, err := ecrypto.Sign(ethMsgHash, privKey)
	require.NoError(t, err)

	ok := verifyFinalizationSignature(pubBytes, msg.Round, msg.CodeCommitment, msg.ParticipantsRoot, msg.GlobalPubKey, msg.PublicCoeffsBz, msg.PubKeyShare, sig)
	if !ok {
		t.Fatal("signature verification failed")
	}

	t.Log("Signature verified successfully!")
	t.Logf("Signature: %s", hex.EncodeToString(sig))
}

func TestEncryptPartialToRequester_Success(t *testing.T) {
	// Generate requester key pair
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("secret-partial-share-data-12345")

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)
	require.NotNil(t, encrypted)
	require.NotNil(t, ephPub)

	// Verify ephemeral pubkey format
	require.Len(t, ephPub, 65)
	require.Equal(t, byte(0x04), ephPub[0])

	// Encrypted should contain nonce (12 bytes for GCM) + ciphertext + tag (16 bytes)
	require.Greater(t, len(encrypted), 12+16)

	// Decrypt and verify
	decrypted, err := decryptPartialFromRequester(requesterPriv, ephPub, encrypted)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted)
}

func TestEncryptPartialToRequester_EmptyPartial(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte{}

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)
	require.NotNil(t, encrypted)
	require.NotNil(t, ephPub)

	decrypted, err := decryptPartialFromRequester(requesterPriv, ephPub, encrypted)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted)
}

func TestEncryptPartialToRequester_LargePartial(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// 1MB partial
	partial := make([]byte, 1024*1024)
	_, err = rand.Read(partial)
	require.NoError(t, err)

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)

	decrypted, err := decryptPartialFromRequester(requesterPriv, ephPub, encrypted)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted)
}

func TestEncryptPartialToRequester_InvalidPubKeyLength(t *testing.T) {
	testCases := []struct {
		name   string
		pubKey []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x04, 0x01, 0x02}},
		{"64 bytes", make([]byte, 64)},
		{"66 bytes", make([]byte, 66)},
		{"33 bytes compressed", make([]byte, 33)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.pubKey) == 33 {
				tc.pubKey[0] = 0x02 // compressed prefix
			}
			_, _, err := encryptPartialToRequester(tc.pubKey, []byte("test"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid requester pubkey")
		})
	}
}

func TestEncryptPartialToRequester_InvalidPubKeyPrefix(t *testing.T) {
	// Generate valid key but corrupt prefix
	priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	pubBytes := ecrypto.FromECDSAPub(&priv.PublicKey)

	testCases := []struct {
		name   string
		prefix byte
	}{
		{"null prefix", 0x00},
		{"compressed even", 0x02},
		{"compressed odd", 0x03},
		{"random prefix", 0xFF},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := make([]byte, len(pubBytes))
			copy(corrupted, pubBytes)
			corrupted[0] = tc.prefix

			_, _, err := encryptPartialToRequester(corrupted, []byte("test"))
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid requester pubkey")
		})
	}
}

func TestEncryptPartialToRequester_MalformedPubKey(t *testing.T) {
	// 65 bytes with 0x04 prefix but garbage data (not a valid point)
	malformed := make([]byte, 65)
	malformed[0] = 0x04
	_, err := rand.Read(malformed[1:])
	require.NoError(t, err)

	_, _, err = encryptPartialToRequester(malformed, []byte("test"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse requester pubkey")
}

func TestEncryptPartialToRequester_UniqueEphemeralKeys(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("test-partial")

	// Call multiple times and verify ephemeral keys differ
	var ephemeralKeys [][]byte
	for range 5 {
		_, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
		require.NoError(t, err)
		ephemeralKeys = append(ephemeralKeys, ephPub)
	}

	// All ephemeral keys should be unique
	for i := range ephemeralKeys {
		for j := i + 1; j < len(ephemeralKeys); j++ {
			require.False(t, bytes.Equal(ephemeralKeys[i], ephemeralKeys[j]),
				"ephemeral keys should be unique for each call")
		}
	}
}

func TestEncryptPartialToRequester_UniqueNonces(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("test-partial")

	// Even with same inputs, nonces should differ
	var nonces [][]byte
	// Derive nonce size from AES-GCM to avoid assuming 12-byte nonces.
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonceSize := gcm.NonceSize()

	for range 5 {
		encrypted, _, err := encryptPartialToRequester(requesterPubBytes, partial)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(encrypted), nonceSize)
		nonce := encrypted[:nonceSize]
		nonces = append(nonces, nonce)
	}

	for i := range nonces {
		for j := i + 1; j < len(nonces); j++ {
			require.False(t, bytes.Equal(nonces[i], nonces[j]),
				"nonces should be unique for each call")
		}
	}
}

func TestEncryptPartialToRequester_DifferentRequesterKeys(t *testing.T) {
	partial := []byte("test-partial")

	// Two different requesters
	requester1Priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requester2Priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	pub1 := ecrypto.FromECDSAPub(&requester1Priv.PublicKey)
	pub2 := ecrypto.FromECDSAPub(&requester2Priv.PublicKey)

	// Encrypt to requester1
	encrypted1, ephPub1, err := encryptPartialToRequester(pub1, partial)
	require.NoError(t, err)

	// Encrypt to requester2
	encrypted2, ephPub2, err := encryptPartialToRequester(pub2, partial)
	require.NoError(t, err)

	// Requester1 can decrypt their own
	decrypted1, err := decryptPartialFromRequester(requester1Priv, ephPub1, encrypted1)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted1)

	// Requester2 can decrypt their own
	decrypted2, err := decryptPartialFromRequester(requester2Priv, ephPub2, encrypted2)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted2)

	// Requester1 CANNOT decrypt requester2's message (wrong shared secret)
	_, err = decryptPartialFromRequester(requester1Priv, ephPub2, encrypted2)
	require.Error(t, err)

	// Requester2 CANNOT decrypt requester1's message
	_, err = decryptPartialFromRequester(requester2Priv, ephPub1, encrypted1)
	require.Error(t, err)
}

func TestEncryptPartialToRequester_TamperedCiphertext(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("test-partial-data")

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)

	// Tamper with ciphertext (flip a bit after nonce)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[15] ^= 0xFF

	// Should fail authentication
	_, err = decryptPartialFromRequester(requesterPriv, ephPub, tampered)
	require.Error(t, err)
}

func TestEncryptPartialToRequester_TamperedNonce(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("test-partial-data")

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)

	// Tamper with nonce
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[0] ^= 0xFF

	// Should fail
	_, err = decryptPartialFromRequester(requesterPriv, ephPub, tampered)
	require.Error(t, err)
}

func TestEncryptPartialToRequester_TruncatedCiphertext(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	partial := []byte("test-partial-data")

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)

	// Truncate ciphertext
	truncated := encrypted[:len(encrypted)-5]

	_, err = decryptPartialFromRequester(requesterPriv, ephPub, truncated)
	require.Error(t, err)
}

func TestEncryptPartialToRequester_BinaryPartial(t *testing.T) {
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Binary data with null bytes and all byte values
	partial := make([]byte, 256)
	for i := range 256 {
		partial[i] = byte(i)
	}

	encrypted, ephPub, err := encryptPartialToRequester(requesterPubBytes, partial)
	require.NoError(t, err)

	decrypted, err := decryptPartialFromRequester(requesterPriv, ephPub, encrypted)
	require.NoError(t, err)
	require.Equal(t, partial, decrypted)
}

// decryptPartialFromRequester is the inverse of encryptPartialToRequester for test verification.
func decryptPartialFromRequester(requesterPrivKey *ecdsa.PrivateKey, ephemeralPubKey []byte, encrypted []byte) ([]byte, error) {
	ephPub, err := ecrypto.UnmarshalPubkey(ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	requesterECIES := ecies.ImportECDSA(requesterPrivKey)
	ephemeralECIES := ecies.ImportECDSAPublic(ephPub)
	sharedBytes, err := requesterECIES.GenerateShared(ephemeralECIES, 32, 0)
	if err != nil {
		return nil, err
	}

	h := hkdf.New(sha256.New, sharedBytes, nil, []byte("dkg-tdh2-partial"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(h, aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if plain == nil {
		return []byte{}, nil
	}

	return plain, nil
}
