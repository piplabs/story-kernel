package platform

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// =============================================================================
// AK pub binding helpers shared between vendor adapters and selfcheck.
//
// On a paravisor-mediated TDX guest, V4.report_data is locked by the
// paravisor at boot to SHA256(VariableData), where VariableData is a
// JSON envelope containing the AK pub in JWK form. The kernel and
// on-chain verifier both need to:
//
//  1. Parse VariableData to find HCLAkPub.n (RSA modulus).
//  2. Convert a DER SubjectPublicKeyInfo (the canonical wire form for
//     RSA pub keys) to a comparable RSA modulus byte string.
//  3. Compare 1 and 2 — equality binds the AK in the bundle to the AK
//     the paravisor measured.
//
// These helpers live in `platform` (not in `paravisor/`) so the
// kernel-side selfcheck (which is in `enclave/tdx`) can reuse them via
// the bundle path without an import cycle.
// =============================================================================

// ExtractHCLAkPubModulus parses the VariableData JSON and returns the
// RSA modulus of the entry whose "kid" is "HCLAkPub". The JSON shape is
// fixed by the OpenHCL paravisor reference implementation:
//
//	{"keys":[{"kid":"HCLAkPub","kty":"RSA","n":"<base64url modulus>","e":"AQAB",...},
//	         {"kid":"HCLEkPub",...}], "vm-configuration":{...}, "user-data":"..."}
//
// The modulus is base64url-encoded without padding (RFC 7517 §3); we
// also tolerate padded encoding for forward-compat. We do NOT build an
// *rsa.PublicKey here — the kernel uses bundle.AKPub (DER) for
// signature verification; this function only returns bytes for modulus
// comparison.
func ExtractHCLAkPubModulus(variableData []byte) ([]byte, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(variableData, &doc); err != nil {
		return nil, fmt.Errorf("parse VariableData JSON: %w", err)
	}
	for _, k := range doc.Keys {
		if k.Kid != "HCLAkPub" {
			continue
		}
		if k.Kty != "RSA" {
			return nil, fmt.Errorf("HCLAkPub.kty=%q, expected RSA", k.Kty)
		}
		if k.N == "" {
			return nil, fmt.Errorf("HCLAkPub.n is empty")
		}
		modulus, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			modulus, err = base64.URLEncoding.DecodeString(k.N)
			if err != nil {
				return nil, fmt.Errorf("decode HCLAkPub.n: %w", err)
			}
		}
		// Strip a leading 0x00 if present. Some encoders prepend the
		// byte for big-endian sign-bit safety on signed-int
		// representations; ExtractRSAModulusFromDER never includes it,
		// so trimming makes the two outputs byte-comparable.
		if len(modulus) > 0 && modulus[0] == 0 {
			modulus = modulus[1:]
		}
		return modulus, nil
	}
	return nil, fmt.Errorf("HCLAkPub entry not found in VariableData JSON")
}

// ExtractRSAModulusFromDER parses a SubjectPublicKeyInfo DER blob and
// returns the RSA modulus as raw big-endian bytes. Output is byte-for-
// byte comparable with ExtractHCLAkPubModulus.
func ExtractRSAModulusFromDER(der []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("ParsePKIXPublicKey: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("AK pub is %T, expected *rsa.PublicKey", pub)
	}
	return new(big.Int).Set(rsaPub.N).Bytes(), nil
}
