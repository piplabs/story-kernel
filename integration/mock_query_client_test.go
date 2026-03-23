package integration

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestMockQC_PerRoundNetworkOverride verifies that SetNetworkByRound takes
// precedence over the default network for the specified round, while other
// rounds still fall back to the default.
func TestMockQC_PerRoundNetworkOverride(t *testing.T) {
	defaultNet := &pb.DKGNetwork{Round: 1, Total: 3, Threshold: 2}
	m := NewMockQueryClient(defaultNet)

	round2Net := &pb.DKGNetwork{Round: 2, Total: 5, Threshold: 3}
	m.SetNetworkByRound(2, round2Net)

	ctx := context.Background()

	// Round 2 should return the per-round override
	got2, err := m.GetDKGNetwork(ctx, "", 2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), got2.GetRound())
	require.Equal(t, uint32(5), got2.GetTotal())

	// Round 1 (no override) should fall back to default
	got1, err := m.GetDKGNetwork(ctx, "", 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), got1.GetRound())
	require.Equal(t, uint32(3), got1.GetTotal())
}

// TestMockQC_PerRoundErrorPrecedence verifies that per-round errors take
// precedence over global errors. This is critical for tests that need
// different error behavior for different rounds.
func TestMockQC_PerRoundErrorPrecedence(t *testing.T) {
	defaultNet := &pb.DKGNetwork{Round: 1, Total: 3, Threshold: 2}
	m := NewMockQueryClient(defaultNet)

	globalErr := fmt.Errorf("global network error")
	roundErr := fmt.Errorf("round 2 not found")

	m.SetGetDKGNetworkError(globalErr)
	m.SetGetDKGNetworkErrorForRound(2, roundErr)

	ctx := context.Background()

	// Round 2: per-round error takes precedence
	_, err := m.GetDKGNetwork(ctx, "", 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "round 2 not found",
		"per-round error should take precedence over global error")

	// Round 1: no per-round error, global error kicks in
	_, err = m.GetDKGNetwork(ctx, "", 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "global network error",
		"global error should apply when no per-round error is set")

	// Clear per-round error, round 2 should now get global error
	m.SetGetDKGNetworkErrorForRound(2, nil)
	_, err = m.GetDKGNetwork(ctx, "", 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "global network error",
		"after clearing per-round error, global error should apply")
}

// TestMockQC_PerRoundRegistrationOverride verifies that SetRegistrationsByRound
// returns per-round registrations for the specified round, while other rounds
// fall back to the default registrations.
func TestMockQC_PerRoundRegistrationOverride(t *testing.T) {
	defaultNet := &pb.DKGNetwork{Round: 1, Total: 3, Threshold: 2}
	m := NewMockQueryClient(defaultNet)

	defaultRegs := []*pb.DKGRegistration{
		{Round: 1, Index: 1, ValidatorAddr: "addr1"},
	}
	m.SetRegistrations(defaultRegs)

	round2Regs := []*pb.DKGRegistration{
		{Round: 2, Index: 1, ValidatorAddr: "addr1"},
		{Round: 2, Index: 2, ValidatorAddr: "addr2"},
	}
	m.SetRegistrationsByRound(2, round2Regs)

	ctx := context.Background()

	// Round 2: per-round registrations
	got2, err := m.GetAllParticipantDKGRegistrations(ctx, "", 2)
	require.NoError(t, err)
	require.Len(t, got2, 2, "round 2 should return per-round registrations")
	require.Equal(t, uint32(2), got2[0].GetRound())

	// Round 1: default registrations
	got1, err := m.GetAllParticipantDKGRegistrations(ctx, "", 1)
	require.NoError(t, err)
	require.Len(t, got1, 1, "round 1 should fall back to default registrations")

	// Round 99 (no override): also falls back to default
	got99, err := m.GetAllParticipantDKGRegistrations(ctx, "", 99)
	require.NoError(t, err)
	require.Len(t, got99, 1, "unknown round should fall back to default registrations")
}

// TestMockQC_FallbackToDefaultNetwork documents the fallback behavior:
// when no per-round override is set, GetDKGNetwork returns the default network
// regardless of the requested round. This can silently "pollute" test conclusions
// if a test requests a round that was never configured.
func TestMockQC_FallbackToDefaultNetwork(t *testing.T) {
	defaultNet := &pb.DKGNetwork{
		Round:     1,
		Total:     3,
		Threshold: 2,
		StartBlockHash: bytes.Repeat([]byte{0xab}, 32),
	}
	m := NewMockQueryClient(defaultNet)

	ctx := context.Background()

	// Requesting any round without per-round override returns the default network.
	// WARNING: this means GetDKGNetwork(round=99) silently succeeds with round-1 data.
	// Tests must explicitly configure per-round overrides or errors for non-default rounds.
	for _, round := range []uint32{1, 2, 50, 99} {
		got, err := m.GetDKGNetwork(ctx, "", round)
		require.NoError(t, err, "round %d should not error", round)
		require.Equal(t, defaultNet.GetRound(), got.GetRound(),
			"round %d: fallback returns default network (round %d), not the requested round",
			round, defaultNet.GetRound())
		require.Equal(t, defaultNet.GetTotal(), got.GetTotal())
	}
}
