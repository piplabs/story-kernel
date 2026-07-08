package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// plaintextFileSealer is a test-only inner Sealer that writes the payload
// verbatim to disk (no encryption). It lets PathBindingSealer tests exercise
// the framing/verification logic without a TEE.
type plaintextFileSealer struct{}

func (plaintextFileSealer) SealToFile(data []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (plaintextFileSealer) UnsealFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func slotPath(root string, round string, commitment string, file string) string {
	return filepath.Join(root, round, commitment, file)
}

func TestPathBindingSealer_RoundTrip(t *testing.T) {
	root := t.TempDir()
	s := NewPathBindingSealer(plaintextFileSealer{})
	path := slotPath(root, "7", "abcd", "ed25519.key")
	want := []byte("super-secret-share")

	if err := s.SealToFile(want, path); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}
	got, err := s.UnsealFromFile(path)
	if err != nil {
		t.Fatalf("UnsealFromFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, want)
	}
}

func TestPathBindingSealer_RejectsRelocationAcrossRounds(t *testing.T) {
	root := t.TempDir()
	s := NewPathBindingSealer(plaintextFileSealer{})

	src := slotPath(root, "7", "abcd", "ed25519.key")
	if err := s.SealToFile([]byte("share-r7"), src); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}

	// Attacker copies round 7's sealed blob into round 8's slot.
	dst := slotPath(root, "8", "abcd", "ed25519.key")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.UnsealFromFile(dst); err == nil {
		t.Fatal("expected relocation across rounds to be rejected, got nil error")
	}
}

func TestPathBindingSealer_RejectsRelocationAcrossKeyType(t *testing.T) {
	root := t.TempDir()
	s := NewPathBindingSealer(plaintextFileSealer{})

	src := slotPath(root, "7", "abcd", "ed25519.key")
	if err := s.SealToFile([]byte("share"), src); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}

	dst := slotPath(root, "7", "abcd", "secp256k1.key")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.UnsealFromFile(dst); err == nil {
		t.Fatal("expected relocation across key type to be rejected, got nil error")
	}
}

func TestPathBindingSealer_RootIndependent(t *testing.T) {
	// The same logical slot under two different store roots must round-trip:
	// binding is on the trailing components, not the absolute path.
	s := NewPathBindingSealer(plaintextFileSealer{})

	rootA := t.TempDir()
	pathA := slotPath(rootA, "7", "abcd", "ed25519.key")
	if err := s.SealToFile([]byte("share"), pathA); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}

	rootB := t.TempDir()
	pathB := slotPath(rootB, "7", "abcd", "ed25519.key")
	raw, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(pathB), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.UnsealFromFile(pathB); err != nil {
		t.Fatalf("same slot under a different root must unseal: %v", err)
	}
}
