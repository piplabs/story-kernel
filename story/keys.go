package story

import (
	"fmt"
)

const (
	// DKGModuleName is the name of the DKG module.
	DKGModuleName = "dkg"

	// StoreKey is the store key for the DKG module.
	StoreKey = DKGModuleName
)

// Collections prefixes from Story DKG module (client/x/dkg/types/keys.go).
const (
	DKGNetworkPrefix        byte = 1
	DKGRegistrationPrefix   byte = 3
	LatestActiveRoundPrefix byte = 4
)

// GetDKGNetworkKey returns the store key for a DKG network.
// Matches story keeper's key: strconv.FormatUint(round, 10).
func GetDKGNetworkKey(_ string, round uint32) []byte {
	key := fmt.Sprintf("%d", round)

	return buildCollectionKey(DKGNetworkPrefix, []byte(key))
}

// GetDKGRegistrationKey returns the store key for a DKG registration.
// Matches story keeper's key: fmt.Sprintf("%d_%s", round, addr.Hex()).
func GetDKGRegistrationKey(_ string, round uint32, validatorAddr string) []byte {
	key := fmt.Sprintf("%d_%s", round, validatorAddr)

	return buildCollectionKey(DKGRegistrationPrefix, []byte(key))
}

// GetLatestActiveRoundKey returns the storage key for the latest active round pointer.
func GetLatestActiveRoundKey() []byte {
	return []byte{LatestActiveRoundPrefix}
}

// buildCollectionKey builds a Cosmos SDK collections store key.
// Cosmos SDK collections.Map with StringKey uses: prefix | key_bytes (no length prefix).
func buildCollectionKey(prefix byte, key []byte) []byte {
	result := make([]byte, 1+len(key))
	result[0] = prefix
	copy(result[1:], key)

	return result
}
