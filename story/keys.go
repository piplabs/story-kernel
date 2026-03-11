package story

import (
	"encoding/binary"
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
	LatestActiveRoundPrefix byte = 4 // Added based on keeper implementation
)

// Where key is "{round}" matching story keeper's strconv.FormatUint(round, 10).
func GetDKGNetworkKey(_ string, round uint32) []byte {
	// Collections uses: prefix | string_key_length (varint) | string_key
	key := fmt.Sprintf("%d", round)

	return buildCollectionKey(DKGNetworkPrefix, []byte(key))
}

// Where key is "{round}_{validator_addr}" matching story keeper's fmt.Sprintf("%d_%s", round, addr.Hex()).
func GetDKGRegistrationKey(_ string, round uint32, validatorAddr string) []byte {
	// Collections uses: prefix | string_key_length (varint) | string_key
	key := fmt.Sprintf("%d_%s", round, validatorAddr)

	return buildCollectionKey(DKGRegistrationPrefix, []byte(key))
}

// GetLatestActiveRoundKey returns the storage key for the latest active round pointer.
func GetLatestActiveRoundKey() []byte {
	// Latest active round stores a string value (the key of the latest active network)
	// It uses a simple Item collection with just the prefix
	return []byte{LatestActiveRoundPrefix}
}

// Collections string keys format: prefix | length_varint | key_bytes.
func buildCollectionKey(prefix byte, key []byte) []byte {
	// Calculate varint size for key length
	keyLen := len(key)
	varintBuf := make([]byte, binary.MaxVarintLen64)
	varintLen := binary.PutUvarint(varintBuf, uint64(keyLen))

	// Build final key: prefix | length | key
	result := make([]byte, 1+varintLen+keyLen)
	result[0] = prefix
	copy(result[1:], varintBuf[:varintLen])
	copy(result[1+varintLen:], key)

	return result
}
