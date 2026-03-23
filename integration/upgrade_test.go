package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
)

// ---------- C: Upgrade & version compatibility tests ----------

// TestUpgrade_DKGStateExtraFieldsIgnored verifies that DKG state JSON files
// containing unknown fields (from a newer version) can still be loaded by the
// current version. This tests forward compatibility of the state format.
//
// In a real upgrade scenario, a newer kernel version may write state.json with
// additional fields. If the operator downgrades or another node runs an older
// version, it must be able to read the state file without errors.
func TestUpgrade_DKGStateExtraFieldsIgnored(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete DKG up to ProcessDeals so state.json is written with real data
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()

	// Locate the state.json file for node 0
	codeCommitmentHex := hex.EncodeToString(cluster.CodeCommitment)
	stateDir := cluster.Servers[0].Cfg.GetDKGStateDir()
	statePath := filepath.Join(stateDir, strconv.FormatUint(uint64(cluster.Round), 10), codeCommitmentHex, "state.json")

	// Read existing state
	data, err := os.ReadFile(statePath)
	require.NoError(t, err, "state.json should exist after ProcessDeals")

	// Parse as generic JSON and inject unknown fields (simulating a newer version)
	var stateMap map[string]interface{}
	err = json.Unmarshal(data, &stateMap)
	require.NoError(t, err)

	stateMap["new_field_from_v2"] = "some_value"
	stateMap["experimental_feature"] = map[string]interface{}{
		"enabled": true,
		"config":  []int{1, 2, 3},
	}

	modifiedData, err := json.MarshalIndent(stateMap, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(statePath, modifiedData, 0o600)
	require.NoError(t, err)

	// Verify LoadDKGState still works with extra fields
	st, err := cluster.Servers[0].DKGStore.LoadDKGState(codeCommitmentHex, cluster.Round)
	require.NoError(t, err, "LoadDKGState should succeed even with unknown JSON fields")
	require.NotNil(t, st)
	require.Greater(t, st.Threshold, uint32(0), "threshold should be preserved")
	require.NotEmpty(t, st.PubKeys, "pub keys should be preserved")
	require.NotEmpty(t, st.Deals, "deals should be preserved")
}

// TestUpgrade_DKGStateMinimalFieldsLoadable verifies that a state.json file
// with only the minimal required fields (threshold + pub_keys) and missing all
// optional fields can be loaded successfully. This tests backward compatibility:
// an older version that never wrote justifications/from_round/public_coeffs
// can still be read by the current version.
func TestUpgrade_DKGStateMinimalFieldsLoadable(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys to get real Ed25519 public keys
	cluster.GenerateAllKeys()

	// Get real pub keys from registrations
	regs := cluster.MockQC.GetCurrentRegistrations()
	pubKeysBase64 := make([]string, len(regs))
	for i, reg := range regs {
		pubKeysBase64[i] = base64.StdEncoding.EncodeToString(reg.GetDkgPubKey())
	}

	// Write a minimal state.json (simulating an old version output)
	// Only threshold and pub_keys — no deals, responses, justifications, from_round, public_coeffs
	minimalState := map[string]interface{}{
		"pub_keys_base_64": pubKeysBase64,
		"threshold":        2,
		"deals":            []interface{}{},
		"responses":        []interface{}{},
	}

	data, err := json.MarshalIndent(minimalState, "", "  ")
	require.NoError(t, err)

	codeCommitmentHex := hex.EncodeToString(cluster.CodeCommitment)
	stateDir := cluster.Servers[0].Cfg.GetDKGStateDir()
	stateFileDir := filepath.Join(stateDir, strconv.FormatUint(uint64(cluster.Round), 10), codeCommitmentHex)
	err = os.MkdirAll(stateFileDir, 0o755)
	require.NoError(t, err)

	statePath := filepath.Join(stateFileDir, "state.json")
	err = os.WriteFile(statePath, data, 0o600)
	require.NoError(t, err)

	// Verify LoadDKGState succeeds
	st, err := cluster.Servers[0].DKGStore.LoadDKGState(codeCommitmentHex, cluster.Round)
	require.NoError(t, err, "LoadDKGState should succeed with minimal fields")
	require.Equal(t, uint32(2), st.Threshold)
	require.Len(t, st.PubKeys, 3)
	require.Empty(t, st.Justifications, "justifications should be empty (missing from JSON)")
	require.Equal(t, uint32(0), st.FromRound, "from_round should default to 0")
	require.Empty(t, st.PublicCoeffs, "public_coeffs should be empty (missing from JSON)")

	// Verify HasDKGState returns true (threshold > 0 and pub keys non-empty)
	has, err := cluster.Servers[0].DKGStore.HasDKGState(codeCommitmentHex, cluster.Round)
	require.NoError(t, err)
	require.True(t, has, "HasDKGState should return true with threshold + pub keys present")

	t.Run("truly_minimal", func(t *testing.T) {
		// Write state with only threshold and pub_keys — no deals or responses at all
		trulyMinimalState := map[string]interface{}{
			"threshold":        2,
			"pub_keys_base_64": pubKeysBase64,
		}

		minData, err := json.MarshalIndent(trulyMinimalState, "", "  ")
		require.NoError(t, err)

		err = os.WriteFile(statePath, minData, 0o600)
		require.NoError(t, err)

		st2, err := cluster.Servers[0].DKGStore.LoadDKGState(codeCommitmentHex, cluster.Round)
		require.NoError(t, err, "LoadDKGState should succeed with truly minimal fields (no deals/responses)")
		require.Equal(t, uint32(2), st2.Threshold)
		require.Len(t, st2.PubKeys, 3)
		require.Empty(t, st2.Deals, "deals should be empty when omitted from JSON")
		require.Empty(t, st2.Responses, "responses should be empty when omitted from JSON")

		has2, err := cluster.Servers[0].DKGStore.HasDKGState(codeCommitmentHex, cluster.Round)
		require.NoError(t, err)
		require.True(t, has2, "HasDKGState should return true with only threshold + pub keys")
	})
}

// TestUpgrade_DistKeyShareMarshalRoundtrip verifies that the DistKeyShare binary
// format is stable: marshal → unmarshal produces an identical structure that can
// be used for valid partial decryption. This catches any accidental format changes.
//
// In a real upgrade, the sealed DistKeyShare is loaded from disk by the new binary.
// If the binary format changed between versions, the unmarshal would silently produce
// corrupted data, leading to invalid partial decryptions.
func TestUpgrade_DistKeyShareMarshalRoundtrip(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete full DKG
	cluster.RunFullDKG()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	// Get the DistKeyShare from cache (populated by FinalizeDKG)
	distKeyShare, ok := cluster.Servers[0].DistKeyShareCache.Get(cluster.Round)
	require.True(t, ok, "DistKeyShareCache should contain round 1 after FinalizeDKG")

	// Marshal → Unmarshal roundtrip
	marshaled, err := store.MarshalDistKeyShare(distKeyShare)
	require.NoError(t, err, "MarshalDistKeyShare should succeed")
	require.NotEmpty(t, marshaled, "marshaled bytes should not be empty")

	restored, err := store.UnmarshalDistKeyShare(marshaled, cluster.Servers[0].Suite)
	require.NoError(t, err, "UnmarshalDistKeyShare should succeed on freshly marshaled data")

	// Verify structural equality
	require.Equal(t, len(distKeyShare.Commits), len(restored.Commits), "commit count mismatch")
	require.Equal(t, distKeyShare.Share.I, restored.Share.I, "share index mismatch")

	origShareBz, err := distKeyShare.Share.V.MarshalBinary()
	require.NoError(t, err)
	restoredShareBz, err := restored.Share.V.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, origShareBz, restoredShareBz, "share value mismatch after roundtrip")

	// Double roundtrip: marshal the restored share again and compare bytes
	marshaled2, err := store.MarshalDistKeyShare(restored)
	require.NoError(t, err)
	require.Equal(t, marshaled, marshaled2, "double roundtrip should produce identical bytes")

	// Functional verification: the restored share should produce valid partial decryptions
	// Replace cache with restored share and verify decryption still works
	cluster.Servers[0].DistKeyShareCache.Set(cluster.Round, restored)

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("upgrade roundtrip test")
	label := []byte("upgrade-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partial decryptions from node 0 (using restored share) and node 1 (original)
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(1): result1.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(1): result1.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted,
		"decryption with roundtripped DistKeyShare should match original plaintext")
}
