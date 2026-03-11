package enclave

import (
	"errors"
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

// OpenFileNoFlock opens a goleveldb FileStorage that gracefully handles
// environments where flock is not supported (e.g., Gramine SGX passthrough files).
// If the initial OpenFile fails with ENOSYS/ENOTSUP, it falls back to
// MemStorage so the application can proceed without file locking.
func OpenFileNoFlock(path string) (storage.Storage, error) {
	stor, err := storage.OpenFile(path, false)
	if err == nil {
		return stor, nil
	}

	if !isFlockUnsupported(err) {
		return nil, err
	}

	log.Warn("LevelDB flock not supported (SGX/Gramine environment), using in-memory storage fallback")

	// Ensure directory exists for other file operations
	if mkErr := os.MkdirAll(path, 0755); mkErr != nil {
		log.Warnf("Failed to create directory %s: %v", path, mkErr)
	}

	return storage.NewMemStorage(), nil
}

// isFlockUnsupported returns true if the error indicates that flock
// is not supported by the underlying filesystem (ENOSYS / ENOTSUP).
// This occurs in Gramine SGX where flock is not implemented for
// passthrough (allowed) files.
func isFlockUnsupported(err error) bool {
	if err == nil {
		return false
	}

	// Check for syscall.Errno directly (wrapped or nested)
	errStr := err.Error()
	if strings.Contains(errStr, "function not implemented") ||
		strings.Contains(errStr, "not supported") {
		return true
	}

	// Check underlying errno
	var checkErr error = err
	for checkErr != nil {
		var errno syscall.Errno
		if errors.As(checkErr, &errno) {
			return errno == syscall.ENOSYS || errno == syscall.ENOTSUP
		}
		// Try to unwrap
		if unwrapper, ok := checkErr.(interface{ Unwrap() error }); ok {
			checkErr = unwrapper.Unwrap()
		} else {
			break
		}
	}

	return false
}
