package platform

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Shared TPM2_Quote helper tests
//
// These exercise the production tpmQuote path against the in-process TPM2
// simulator. No TDX hardware is required.
//
// AK provisioning runs at AKHandleParavisor: this is the only persistent
// handle that production TPM2_Quote callers reach (the paravisor vendor
// reads the paravisor-provisioned AK there). The direct vendor does
// not call TPMQuote — it emits raw V4 quotes — so there is no second
// production handle to cover here. The simulator-side
// CreatePrimary+EvictControl mimics what the OpenHCL paravisor does at
// boot on a paravisor-mediated TDX guest.
// =============================================================================

// provisionParavisorAKOnSim provisions the production AK template at
// AKHandleParavisor on the simulator. Tests use this so the helper's
// RSASSA-SHA256 enforcement code paths are reached. AKHandleParavisor
// matches what the paravisor vendor reads in production, so handle
// drift between production and tests surfaces here.
func provisionParavisorAKOnSim(t *testing.T, sim *simulator.Simulator) {
	t.Helper()
	pub := AKTemplate()
	primaryHandle, _, err := tpm2.CreatePrimary(sim, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", pub)
	require.NoError(t, err)
	defer tpm2.FlushContext(sim, primaryHandle)
	require.NoError(t, tpm2.EvictControl(sim, "", tpm2.HandleOwner, primaryHandle, AKHandleParavisor))
}

func TestTPMQuote_HappyPath(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAKOnSim(t, sim)

	qd := []byte("hello-world-binding")
	attest, sigBlob, err := TPMQuote(sim, AKHandleParavisor, qd)
	require.NoError(t, err)
	require.NotEmpty(t, attest)
	require.NotEmpty(t, sigBlob)

	// Decode the signature blob and assert RSASSA-SHA256.
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(sigBlob))
	require.NoError(t, err)
	require.Equal(t, ExpectedSigAlg, sig.Alg)
	require.NotNil(t, sig.RSA)
	require.Equal(t, ExpectedHashAlg, sig.RSA.HashAlg)
	require.Len(t, sig.RSA.Signature, 256, "RSA-2048 sig must be 256 bytes")

	// Verify the signature using the AK pub extracted from the simulator.
	akDER, err := ReadAKPubDER(sim, AKHandleParavisor)
	require.NoError(t, err)
	pk, err := x509.ParsePKIXPublicKey(akDER)
	require.NoError(t, err)
	rsaPub, ok := pk.(*rsa.PublicKey)
	require.True(t, ok)

	digest := sha256.Sum256(attest)
	require.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig.RSA.Signature))

	// Decode the attestation; assert qualifyingData matches.
	attestData, err := tpm2.DecodeAttestationData(attest)
	require.NoError(t, err)
	require.Equal(t, tpm2.TagAttestQuote, attestData.Type)
	require.Equal(t, tpmutil.U16Bytes(qd), attestData.ExtraData)
}

func TestTPMQuote_QualifyingDataTooLong(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAKOnSim(t, sim)

	tooLong := make([]byte, tpmQualifyingDataMax+1)
	_, _, err = TPMQuote(sim, AKHandleParavisor, tooLong)
	require.Error(t, err)
	require.Contains(t, err.Error(), "qualifyingData length")
}

func TestTPMQuote_NilQualifyingDataAccepted(t *testing.T) {
	t.Parallel()
	// Empty qualifyingData is legal: TPM signs the TPMS_ATTEST with
	// ExtraData=empty. The on-chain verifier handles zero-length and
	// non-zero-length identically. A self-check that signs []byte{}
	// must work even on a brand-new vTPM.
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAKOnSim(t, sim)

	attest, sig, err := TPMQuote(sim, AKHandleParavisor, nil)
	require.NoError(t, err)
	require.NotEmpty(t, attest)
	require.NotEmpty(t, sig)
}

func TestTPMQuote_NilPCRSelectionAccepted(t *testing.T) {
	t.Parallel()
	// Same simulator + AK setup; this just documents the design choice
	// that an empty PCR selection is the production path. The tpmQuote
	// helper hard-codes the empty selection internally so the test is
	// satisfied by any successful Quote.
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAKOnSim(t, sim)

	_, _, err = TPMQuote(sim, AKHandleParavisor, []byte("x"))
	require.NoError(t, err)
}

// =============================================================================
// ReadAKPubDER tests
// =============================================================================

func TestReadAKPubDER_RSA2048(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAKOnSim(t, sim)

	der, err := ReadAKPubDER(sim, AKHandleParavisor)
	require.NoError(t, err)
	require.NotEmpty(t, der)

	pk, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)
	rsaPub, ok := pk.(*rsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, 2048, rsaPub.N.BitLen())
}

func TestReadAKPubDER_HandleEmpty(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	// Reading an unprovisioned handle returns a TPM error.
	_, err = ReadAKPubDER(sim, AKHandleParavisor)
	require.Error(t, err)
}
