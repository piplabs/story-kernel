package tdx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	tpmclient "github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// =============================================================================
// TPM device abstraction.
//
// Production wraps /dev/tpmrm0 (resource-managed kernel device, kernel
// >= 4.12) with a fallback to /dev/tpm0. Tests use go-tpm-tools/simulator
// which exposes the same io.ReadWriteCloser surface.
// =============================================================================

// TPMDevice is the minimal TPM interface go-tpm uses to issue TPM2 commands.
type TPMDevice = io.ReadWriteCloser

// openSystemTPM returns the host's TPM device. Prefers /dev/tpmrm0 (kernel
// resource-managed; serializes commands at the driver layer) and falls back
// to /dev/tpm0 (raw, no kernel-side serialization — caller takes the lock).
func openSystemTPM() (TPMDevice, error) {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		rwc, err := tpm2.OpenTPM(path)
		if err == nil {
			return rwc, nil
		}
	}
	return nil, fmt.Errorf("tdx: no TPM device available at /dev/tpmrm0 or /dev/tpm0")
}

// failClosedTPM is registered when openSystemTPM fails. Every Read/Write on
// it returns the wrapped initialization error, so any TPM operation through
// this device fails loudly rather than silently returning empty bytes.
type failClosedTPM struct {
	err error
}

func (f failClosedTPM) Read([]byte) (int, error) {
	return 0, fmt.Errorf("tdx: TPM unavailable: %w", f.err)
}

func (f failClosedTPM) Write([]byte) (int, error) {
	return 0, fmt.Errorf("tdx: TPM unavailable: %w", f.err)
}

func (f failClosedTPM) Close() error { return nil }

// =============================================================================
// Persistent primary key handle.
//
// We use the conventional storage-root key handle 0x81000001 (per TCG TPM
// 2.0 Provisioning Guidance, table 2). This handle is stable across reboots
// once made persistent via TPM2_EvictControl. go-tpm-tools' NewCachedKey
// does the create + evict automatically and returns an existing key when
// the handle template matches.
//
// Lifecycle:
//   - First boot: create primary via tpm2.CreatePrimary, evict to handle.
//   - Subsequent boots: tpm2.ReadPublic on handle; reuse if template matches.
//   - TPM clear (operator action) wipes the persistent slot; next boot
//     recreates and re-evicts.
//
// Operators must keep this handle reserved. If a deployment site already
// uses 0x81000001 for another purpose, change this constant and rebuild.
// Alternative handles in the same range: 0x81000010, 0x81000020.
// =============================================================================

// primaryKeyHandle is the SRK-style persistent handle used by the TDX
// backend. Re-export from go-tpm-tools where it's named SRKReservedHandle.
// Numerically this is 0x81000001, matching TCG TPM 2.0 Provisioning
// Guidance table 2 for the storage primary key.
const primaryKeyHandle = tpmclient.SRKReservedHandle // 0x81000001 per TCG provisioning guidance

// =============================================================================
// Sealed-blob wire format.
//
// Single contiguous byte slice. Byte-precise so the format can be
// re-implemented in a different language if ever needed; the version byte
// gates future format extensions (e.g., uint32 ciphertext_len for >64 KiB
// payloads, which would bump version to 0x0002).
//
//   Offset  Size   Field                  Notes
//   ─────────────────────────────────────────────────────────────────────────
//      0     4   magic                    "TXS1" (0x54, 0x58, 0x53, 0x31)
//      4     2   version (uint16 BE)      0x0001
//      6     2   reserved                 0x0000
//      8     1   bootstrap_flag           0x01 if sealed in bootstrap mode
//      9     1   provider_count           providers active at seal time
//     10     2   sealed_priv_len (BE)     TPM2B_PRIVATE marshaled length
//     12     2   sealed_pub_len  (BE)     TPM2B_PUBLIC  marshaled length
//     14     2   ciphertext_len  (BE)     AES-GCM ciphertext+tag length
//     16     2   reserved                 0x0000
//     18    N1   sealed_priv              TPM2B_PRIVATE bytes
//   18+N1   N2   sealed_pub               TPM2B_PUBLIC  bytes
//   ...    12   aes_nonce                GCM nonce
//   ...     M   aes_ciphertext           AES-256-GCM ciphertext + 16B tag
//   ─────────────────────────────────────────────────────────────────────────
//
// AAD: bytes[0:18] (the header). This binds magic, version, bootstrap flag,
// provider count, and lengths to the ciphertext: tampering with any header
// field breaks the GCM tag. The TPM-sealed key fields are not in the AAD
// because the TPM enforces their integrity via its own sealed-object MAC.
// =============================================================================

const (
	sealedBlobMagic     = "TXS1"
	sealedBlobVersion   = uint16(1)
	sealedBlobHeaderLen = 18
	aesGCMNonceLen      = 12
	aesGCMTagLen        = 16
	aesKeyLen           = 32
)

// Header field offsets in the wire format.
const (
	hdrOffMagic         = 0
	hdrOffVersion       = 4
	hdrOffReserved1     = 6
	hdrOffBootstrap     = 8
	hdrOffProviderCount = 9
	hdrOffPrivLen       = 10
	hdrOffPubLen        = 12
	hdrOffCipherLen     = 14
	hdrOffReserved2     = 16
)

var (
	errSealedBlobTooShort       = errors.New("tdx: sealed blob too short for header")
	errSealedBlobBadMagic       = errors.New("tdx: sealed blob has wrong magic")
	errSealedBlobBadVersion     = errors.New("tdx: unsupported sealed-blob version")
	errSealedBlobLengthMismatch = errors.New("tdx: sealed blob length fields don't match buffer")
	errCiphertextOverflow       = errors.New("tdx: ciphertext exceeds 65535-byte wire limit")
)

// =============================================================================
// Policy construction.
// =============================================================================

// sealPolicyMeta is metadata returned alongside the policy digest. It tells
// the caller whether we're in bootstrap mode (so the self-check can emit
// the right WARN log) and which branch digests were combined.
type sealPolicyMeta struct {
	BranchDigests [][]byte // populated branches in supportedProviders order
	BranchPCRs    [][]int  // PCR indexes per branch (for diagnostics)
	Hash          tpm2.Algorithm
	Bootstrap     bool // true if no provider had ExpectedDigest set
}

// buildSealPolicy returns the policy digest that, when satisfied at unseal
// time, will release the sealed key. Each provider with a populated
// ExpectedDigest contributes one PolicyPCR branch; PolicyOR combines them.
//
// If exactly one provider has a populated ExpectedDigest, no PolicyOR is
// used — the policy is just PolicyPCR for that branch. PolicyOR with one
// branch is legal but yields a different digest than the bare PolicyPCR;
// we prefer the simpler form.
//
// If ZERO providers have a populated ExpectedDigest, this is bootstrap
// mode: we measure the current PCR digest and use it as the single-branch
// policy. The startup self-check emits the WARN log directing the operator
// to paste the captured digest into source.
func buildSealPolicy(tpm io.ReadWriter, providers []ProviderPolicy) ([]byte, *sealPolicyMeta, error) {
	if len(providers) == 0 {
		return nil, nil, errors.New("tdx: no providers configured")
	}

	hashAlg := providers[0].Hash
	for _, p := range providers {
		if p.Hash != hashAlg {
			return nil, nil, fmt.Errorf("tdx: heterogeneous Hash across providers (got %v and %v)", hashAlg, p.Hash)
		}
	}

	// Compute each populated branch's policy digest in its own trial session.
	meta := &sealPolicyMeta{Hash: hashAlg}
	for _, p := range providers {
		if p.ExpectedDigest == nil {
			continue
		}
		digest, err := computeBranchPolicy(tpm, p.PCRSelection, p.ExpectedDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("tdx: branch %q policy: %w", p.Name, err)
		}
		meta.BranchDigests = append(meta.BranchDigests, digest)
		meta.BranchPCRs = append(meta.BranchPCRs, p.PCRs)
	}

	// Bootstrap mode: read current PCR state, treat it as the only branch.
	if len(meta.BranchDigests) == 0 {
		boot := providers[0]
		curDigest, err := readCurrentPCRDigest(tpm, boot.PCRSelection)
		if err != nil {
			return nil, nil, fmt.Errorf("tdx: bootstrap PCR digest: %w", err)
		}
		digest, err := computeBranchPolicy(tpm, boot.PCRSelection, curDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("tdx: bootstrap policy: %w", err)
		}
		meta.BranchDigests = [][]byte{digest}
		meta.BranchPCRs = [][]int{boot.PCRs}
		meta.Bootstrap = true
		return digest, meta, nil
	}

	// Single configured branch: just return that branch's PolicyPCR digest.
	if len(meta.BranchDigests) == 1 {
		return meta.BranchDigests[0], meta, nil
	}

	// Multi-branch: combine via PolicyOR in a fresh trial session.
	finalDigest, err := computePolicyOr(tpm, meta.BranchDigests, hashAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx: PolicyOR digest: %w", err)
	}
	return finalDigest, meta, nil
}

// computeBranchPolicy runs PolicyPCR(expectedDigest, sel) inside a trial
// session and returns the resulting policy digest. The session is flushed
// before return so we don't leak handles.
func computeBranchPolicy(tpm io.ReadWriter, sel tpm2.PCRSelection, expectedDigest []byte) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(tpm,
		tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil,
		tpm2.SessionTrial,
		tpm2.AlgNull, sel.Hash)
	if err != nil {
		return nil, fmt.Errorf("StartAuthSession trial: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(tpm, sess) }()

	if err := tpm2.PolicyPCR(tpm, sess, expectedDigest, sel); err != nil {
		return nil, fmt.Errorf("PolicyPCR: %w", err)
	}
	return tpm2.PolicyGetDigest(tpm, sess)
}

// computePolicyOr replays each branch's PolicyPCR (using its own trial
// session) and then runs PolicyOR on the digests. Since legacy/tpm2 lacks
// a PolicyRestart helper, we open one trial session per call and use only
// PolicyOr at the top — the per-branch digests are already computed.
func computePolicyOr(tpm io.ReadWriter, branchDigests [][]byte, hashAlg tpm2.Algorithm) ([]byte, error) {
	sess, _, err := tpm2.StartAuthSession(tpm,
		tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil,
		tpm2.SessionTrial,
		tpm2.AlgNull, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("StartAuthSession trial OR: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(tpm, sess) }()

	digests := make([]tpmutil.U16Bytes, len(branchDigests))
	for i, d := range branchDigests {
		digests[i] = tpmutil.U16Bytes(d)
	}
	if err := tpm2.PolicyOr(tpm, sess, tpm2.TPMLDigest{Digests: digests}); err != nil {
		return nil, fmt.Errorf("PolicyOr: %w", err)
	}
	return tpm2.PolicyGetDigest(tpm, sess)
}

// readCurrentPCRDigest reads the requested PCRs and returns
// hash(concat(pcr_values_in_index_order)). Used both at seal time
// (bootstrap mode capture) and at self-check time (digest reporting).
func readCurrentPCRDigest(tpm io.ReadWriter, sel tpm2.PCRSelection) ([]byte, error) {
	values, err := readPCRs(tpm, sel)
	if err != nil {
		return nil, err
	}
	return computePCRDigest(sel, values), nil
}

// readPCRs reads the listed PCRs in a single TPM2_PCR_Read.
func readPCRs(tpm io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error) {
	values, err := tpm2.ReadPCRs(tpm, sel)
	if err != nil {
		return nil, fmt.Errorf("ReadPCRs %v: %w", sel.PCRs, err)
	}
	return values, nil
}

// computePCRDigest returns the hash of the PCR values concatenated in
// ascending PCR index order — the same digest the TPM computes for
// PolicyPCR. The digest algorithm is fixed to SHA-256 here; if a future
// hash algorithm is added, extend this switch.
func computePCRDigest(sel tpm2.PCRSelection, values map[int][]byte) []byte {
	sorted := append([]int(nil), sel.PCRs...)
	sort.Ints(sorted)
	switch sel.Hash {
	case tpm2.AlgSHA256:
		h := sha256.New()
		for _, idx := range sorted {
			h.Write(values[idx])
		}
		return h.Sum(nil)
	default:
		// A nil return would silently disable PCR binding in PolicyPCR. Panic
		// here so any future hash-algorithm addition forces an explicit code
		// path.
		panic(fmt.Sprintf("tdx: computePCRDigest: unsupported hash algorithm 0x%04x — extend this switch", uint16(sel.Hash)))
	}
}

// =============================================================================
// Hybrid wrap: TPM seals a 32B AES-256 key; payload is AES-256-GCM under it.
//
// TPM2 has a small TPM2B_SENSITIVE_DATA limit (~128 bytes in practice;
// platform-dependent). Sealing arbitrary-sized payloads directly is awkward.
// Sealing only the 32-byte AES key keeps the TPM operation O(1) while AES-GCM
// handles the bulk encryption.
// =============================================================================

// ensurePrimaryKey loads the persistent primary key from primaryKeyHandle,
// creating + evicting it on first use. Uses go-tpm-tools' NewCachedKey
// which already does the create+evict-on-mismatch dance.
//
// RSA template chosen for broad TPM2 firmware compatibility — ECC SRK
// works on TPMs with NIST P-256 but not all in-TD swtpm builds enable
// ECC. Changing this template is a sealed-blob compatibility break: every
// blob sealed under the old template becomes unsealable on a TPM whose
// 0x81000001 has been re-evicted to a new primary. Do not switch the
// template without a wire-format version bump.
func ensurePrimaryKey(tpm io.ReadWriter) (*tpmclient.Key, error) {
	key, err := tpmclient.NewCachedKey(tpm, tpm2.HandleOwner, tpmclient.SRKTemplateRSA(), primaryKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("ensure primary key: %w", err)
	}
	return key, nil
}

// tdxSeal seals plaintext under the supplied providers' policy. Returns the
// wire-format sealed blob.
func tdxSeal(tpm io.ReadWriter, plaintext []byte, providers []ProviderPolicy) ([]byte, error) {
	if len(plaintext) > 0xFFFF-aesGCMTagLen {
		return nil, errCiphertextOverflow
	}

	policyDigest, meta, err := buildSealPolicy(tpm, providers)
	if err != nil {
		return nil, err
	}

	// 1) Acquire AES key + nonce from the TPM RNG. Symmetric-key bytes are
	//    the secret being protected; routing them through the TPM RNG keeps
	//    the trust chain inside the same trust root that holds the sealed
	//    object.
	//
	//    Defer-zero immediately after acquisition so every error path below
	//    (TPM2_Seal failure, length mismatches, etc.) clears the AES key
	//    from the heap before unwinding. Acquiring then deferring before
	//    any error-returning call eliminates a class of "key leaked on
	//    failure path" bugs.
	keyBytes, err := tpm2.GetRandom(tpm, aesKeyLen)
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetRandom key: %w", err)
	}
	defer zeroBytes(keyBytes)
	if len(keyBytes) != aesKeyLen {
		return nil, fmt.Errorf("TPM2_GetRandom returned %d bytes, want %d", len(keyBytes), aesKeyLen)
	}
	nonceBytes, err := tpm2.GetRandom(tpm, aesGCMNonceLen)
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetRandom nonce: %w", err)
	}
	if len(nonceBytes) != aesGCMNonceLen {
		return nil, fmt.Errorf("TPM2_GetRandom returned %d nonce bytes, want %d", len(nonceBytes), aesGCMNonceLen)
	}

	// 2) Seal the AES key under the persistent primary, bound to policyDigest.
	primary, err := ensurePrimaryKey(tpm)
	if err != nil {
		return nil, err
	}
	defer primary.Close()

	priv, pub, err := tpm2.Seal(tpm, primary.Handle(), "", "", policyDigest, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Seal: %w", err)
	}
	if len(priv) > 0xFFFF || len(pub) > 0xFFFF {
		return nil, fmt.Errorf("tdx: TPM blob exceeds wire limit (priv=%d pub=%d)", len(priv), len(pub))
	}

	// 3) Build header for AAD binding before AES-GCM seal.
	header := make([]byte, sealedBlobHeaderLen)
	copy(header[hdrOffMagic:hdrOffMagic+4], sealedBlobMagic)
	binary.BigEndian.PutUint16(header[hdrOffVersion:hdrOffVersion+2], sealedBlobVersion)
	if meta.Bootstrap {
		header[hdrOffBootstrap] = 0x01
	}
	header[hdrOffProviderCount] = byte(len(providers))
	binary.BigEndian.PutUint16(header[hdrOffPrivLen:hdrOffPrivLen+2], uint16(len(priv)))
	binary.BigEndian.PutUint16(header[hdrOffPubLen:hdrOffPubLen+2], uint16(len(pub)))
	cipherLen := uint16(len(plaintext) + aesGCMTagLen)
	binary.BigEndian.PutUint16(header[hdrOffCipherLen:hdrOffCipherLen+2], cipherLen)

	// 4) AES-256-GCM: seal plaintext under keyBytes, AAD = header.
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonceBytes, plaintext, header)

	// 5) Concatenate wire format. The keyBytes deferred-zero above
	//    handles the heap cleanup; this function's only return value is
	//    the wire-format blob.
	out := make([]byte, 0, sealedBlobHeaderLen+len(priv)+len(pub)+aesGCMNonceLen+len(ciphertext))
	out = append(out, header...)
	out = append(out, priv...)
	out = append(out, pub...)
	out = append(out, nonceBytes...)
	out = append(out, ciphertext...)

	return out, nil
}

// errNoProviderMatches is returned when no configured provider's
// ExpectedDigest matches the current PCR state. The caller (Unseal) treats
// this as a fail-closed condition: the running TD has not booted into any
// of the policy states under which the blob was sealed.
var errNoProviderMatches = errors.New("tdx: no provider matches current PCR state")

// tdxUnseal reverses tdxSeal. The providers slice must reproduce the
// sealing-time policy *for the branches the current host can satisfy*; the
// TPM enforces the actual PCR values match at unseal time.
//
// Order invariant:
// PolicyPCR(matching branch's expected digest) MUST run before PolicyOR(all
// populated branch trial digests). TPM2 session state is order-sensitive;
// reversing the two corrupts the policy digest the session computes and
// TPM2_Unseal rejects the session as unauthorized. PolicyOR alone over the
// branch trial digests does NOT bind the session to actual PCR values —
// PolicyPCR is what the TPM uses to enforce the running PCR contents.
func tdxUnseal(tpm io.ReadWriter, blob []byte, providers []ProviderPolicy) ([]byte, error) {
	if len(blob) < sealedBlobHeaderLen {
		return nil, errSealedBlobTooShort
	}
	if string(blob[hdrOffMagic:hdrOffMagic+4]) != sealedBlobMagic {
		return nil, errSealedBlobBadMagic
	}
	version := binary.BigEndian.Uint16(blob[hdrOffVersion : hdrOffVersion+2])
	if version != sealedBlobVersion {
		return nil, fmt.Errorf("%w: %d", errSealedBlobBadVersion, version)
	}

	privLen := int(binary.BigEndian.Uint16(blob[hdrOffPrivLen : hdrOffPrivLen+2]))
	pubLen := int(binary.BigEndian.Uint16(blob[hdrOffPubLen : hdrOffPubLen+2]))
	cipherLen := int(binary.BigEndian.Uint16(blob[hdrOffCipherLen : hdrOffCipherLen+2]))

	expectedTotal := sealedBlobHeaderLen + privLen + pubLen + aesGCMNonceLen + cipherLen
	if len(blob) != expectedTotal {
		return nil, fmt.Errorf("%w: have %d want %d", errSealedBlobLengthMismatch, len(blob), expectedTotal)
	}

	header := blob[:sealedBlobHeaderLen]
	cursor := sealedBlobHeaderLen
	priv := blob[cursor : cursor+privLen]
	cursor += privLen
	pub := blob[cursor : cursor+pubLen]
	cursor += pubLen
	nonce := blob[cursor : cursor+aesGCMNonceLen]
	cursor += aesGCMNonceLen
	ciphertext := blob[cursor : cursor+cipherLen]

	// Collect populated providers into a flat slice so we can iterate
	// once for matching, once for trial-digest computation. Filtering
	// here keeps the rest of the function free of `if ExpectedDigest ==
	// nil` checks.
	populated := make([]ProviderPolicy, 0, len(providers))
	for _, p := range providers {
		if p.ExpectedDigest != nil {
			populated = append(populated, p)
		}
	}

	hashAlg := providers[0].Hash

	// 1) Load the sealed object under the persistent primary.
	primary, err := ensurePrimaryKey(tpm)
	if err != nil {
		return nil, err
	}
	defer primary.Close()

	itemHandle, _, err := tpm2.Load(tpm, primary.Handle(), "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Load sealed item: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(tpm, itemHandle) }()

	// 2) Bootstrap mode (no populated branches): replay current PCR state.
	if len(populated) == 0 {
		return unsealBootstrap(tpm, itemHandle, providers, hashAlg, nonce, ciphertext, header)
	}

	// 3) Strict mode: read the current PCR digest for the populated set's
	//    PCRs once, then find the matching branch. We assume every
	//    populated branch covers the same PCR set (in practice all entries
	//    in supportedProviders share the same PCR list); if a future
	//    deployment lists heterogeneous PCR sets this matching loop must
	//    be widened to read each branch's PCR set independently.
	currentDigest, err := readCurrentPCRDigest(tpm, populated[0].PCRSelection)
	if err != nil {
		return nil, fmt.Errorf("read current PCR digest: %w", err)
	}

	matchingIdx := -1
	for i, p := range populated {
		if bytes.Equal(currentDigest, p.ExpectedDigest) {
			matchingIdx = i
			break
		}
	}
	if matchingIdx == -1 {
		return nil, errNoProviderMatches
	}

	// 4) Compute trial-session digests for ALL populated branches. These
	//    are the inputs PolicyOR requires — raw ExpectedDigest values are
	//    NOT the same as PolicyPCR's resulting digest in a trial session.
	trialDigests := make([][]byte, 0, len(populated))
	for _, p := range populated {
		d, err := computeBranchPolicy(tpm, p.PCRSelection, p.ExpectedDigest)
		if err != nil {
			return nil, fmt.Errorf("multi-branch unseal: branch %q: %w", p.Name, err)
		}
		trialDigests = append(trialDigests, d)
	}

	// 5) Build the real session: PolicyPCR(matching) [+ PolicyOR(all)].
	sess, _, err := tpm2.StartAuthSession(tpm,
		tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("StartAuthSession unseal: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(tpm, sess) }()

	matched := populated[matchingIdx]
	sel := tpm2.PCRSelection{Hash: hashAlg, PCRs: append([]int(nil), matched.PCRs...)}
	if err := tpm2.PolicyPCR(tpm, sess, matched.ExpectedDigest, sel); err != nil {
		return nil, fmt.Errorf("PolicyPCR matching branch %q: %w", matched.Name, err)
	}
	if len(populated) > 1 {
		digests := make([]tpmutil.U16Bytes, len(trialDigests))
		for i, d := range trialDigests {
			digests[i] = tpmutil.U16Bytes(d)
		}
		if err := tpm2.PolicyOr(tpm, sess, tpm2.TPMLDigest{Digests: digests}); err != nil {
			return nil, fmt.Errorf("PolicyOr unseal: %w", err)
		}
	}

	// 6) Unseal under the policy session.
	keyBytes, err := tpm2.UnsealWithSession(tpm, sess, itemHandle, "")
	if err != nil {
		return nil, fmt.Errorf("TPM2_Unseal: %w", err)
	}
	defer zeroBytes(keyBytes)
	if len(keyBytes) != aesKeyLen {
		return nil, fmt.Errorf("tdx: unsealed key length %d, want %d", len(keyBytes), aesKeyLen)
	}

	return aesGCMOpen(keyBytes, nonce, ciphertext, header)
}

// unsealBootstrap is the bootstrap-mode unseal path: no populated branch is
// available, so we replay the current PCR state captured at seal time and
// hope it matches. The TPM enforces the equality at unseal time.
func unsealBootstrap(
	tpm io.ReadWriter,
	itemHandle tpmutil.Handle,
	providers []ProviderPolicy,
	hashAlg tpm2.Algorithm,
	nonce, ciphertext, header []byte,
) ([]byte, error) {
	boot := providers[0]
	curDigest, err := readCurrentPCRDigest(tpm, boot.PCRSelection)
	if err != nil {
		return nil, fmt.Errorf("bootstrap unseal: read current digest: %w", err)
	}
	sess, _, err := tpm2.StartAuthSession(tpm,
		tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("bootstrap unseal: StartAuthSession: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(tpm, sess) }()

	sel := tpm2.PCRSelection{Hash: hashAlg, PCRs: append([]int(nil), boot.PCRs...)}
	if err := tpm2.PolicyPCR(tpm, sess, curDigest, sel); err != nil {
		return nil, fmt.Errorf("bootstrap unseal: PolicyPCR: %w", err)
	}

	keyBytes, err := tpm2.UnsealWithSession(tpm, sess, itemHandle, "")
	if err != nil {
		return nil, fmt.Errorf("bootstrap unseal: TPM2_Unseal: %w", err)
	}
	defer zeroBytes(keyBytes)
	if len(keyBytes) != aesKeyLen {
		return nil, fmt.Errorf("tdx: bootstrap unsealed key length %d, want %d", len(keyBytes), aesKeyLen)
	}
	return aesGCMOpen(keyBytes, nonce, ciphertext, header)
}

// aesGCMOpen decrypts ciphertext under keyBytes using AES-256-GCM with the
// header as AAD. Used by both the strict and bootstrap unseal paths.
func aesGCMOpen(keyBytes, nonce, ciphertext, header []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM Open: %w", err)
	}
	return plaintext, nil
}

// zeroBytes overwrites b with zeros. Best-effort; the Go compiler is free
// to elide this on dead values, but keeping the call documents intent.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
