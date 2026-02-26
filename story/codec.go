package story

import (
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
)

// MakeCodec creates and returns the codec for Story chain types.
func MakeCodec() *codec.ProtoCodec {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)

	return codec.NewProtoCodec(interfaceRegistry)
}
