package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func TestValidateRegistrations_Valid(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 5}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb"},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc"},
	}

	err := validateRegistrations(regs, network, 5)
	require.NoError(t, err)
}

func TestValidateRegistrations_CountMismatch(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 5, Round: 1}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 1, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 1, ValidatorAddr: "0xbbb"},
	}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration count 2 does not match network total 5")
}

func TestValidateRegistrations_DuplicateIndex(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 1}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 1, ValidatorAddr: "0xaaa"},
		{Index: 1, Round: 1, ValidatorAddr: "0xbbb"}, // duplicate
		{Index: 3, Round: 1, ValidatorAddr: "0xccc"},
	}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate registration index 1")
}

func TestValidateRegistrations_WrongRound(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 2, Round: 5}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 3, ValidatorAddr: "0xbbb"}, // wrong round
	}

	err := validateRegistrations(regs, network, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration round 3 does not match requested round 5")
	assert.Contains(t, err.Error(), "0xbbb")
}

func TestValidateRegistrations_EmptyRegistrations(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 1}
	regs := []*pb.DKGRegistration{}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration count 0 does not match network total 3")
}

func TestValidateRegistrations_TotalZero(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 0, Round: 1}
	regs := []*pb.DKGRegistration{}

	// Zero registrations with zero total should pass.
	err := validateRegistrations(regs, network, 1)
	require.NoError(t, err)
}

func TestValidateRegistrations_SingleRegistration(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 1, Round: 10}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 10, ValidatorAddr: "0xaaa"},
	}

	err := validateRegistrations(regs, network, 10)
	require.NoError(t, err)
}

func TestValidateRegistrations_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		network     *pb.DKGNetwork
		regs        []*pb.DKGRegistration
		round       uint32
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid 3 of 3",
			network: &pb.DKGNetwork{Total: 3, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
				{Index: 2, Round: 1},
				{Index: 3, Round: 1},
			},
			round:   1,
			wantErr: false,
		},
		{
			name:    "count mismatch (fewer regs)",
			network: &pb.DKGNetwork{Total: 3, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "registration count",
		},
		{
			name:    "count mismatch (more regs)",
			network: &pb.DKGNetwork{Total: 1, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
				{Index: 2, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "registration count",
		},
		{
			name:    "duplicate index",
			network: &pb.DKGNetwork{Total: 2, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 5, Round: 1},
				{Index: 5, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "duplicate registration index",
		},
		{
			name:    "wrong round on first registration",
			network: &pb.DKGNetwork{Total: 1, Round: 10},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 99},
			},
			round:       10,
			wantErr:     true,
			errContains: "registration round 99 does not match requested round 10",
		},
		{
			name:    "wrong round on second registration",
			network: &pb.DKGNetwork{Total: 2, Round: 5},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 5},
				{Index: 2, Round: 7},
			},
			round:       5,
			wantErr:     true,
			errContains: "registration round 7 does not match requested round 5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateRegistrations(tc.regs, tc.network, tc.round)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
