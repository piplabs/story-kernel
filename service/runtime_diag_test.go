package service

// This test uses ACTUAL on-chain data from a live network run to verify
// whether the pubShares reconstruct the global key.
// If this test FAILS, it confirms the live DKG produced inconsistent data.

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	"github.com/stretchr/testify/require"
)

// Data from user's live run (round=1, uuid=1, threshold=2, 3 validators)
// Validators registered in this order:
//   index=1: 0xC6cB20293dD838C3E839198B9F753c6Ed29e0c9B
//   index=2: 0xa5D284381bB6905C6954802F1fc22C84E7d15Df6
//   index=3: 0xc8AE9Ca51859a4DB382EC0F4137A74155Cf936FB
//
// Global pub key from Finalized event (Kyber MarshalBinary, 32 bytes):
//   ee293ab357ebe7775d1038a0f6e88987b3ea96a66d201b2dde850016542d5141
//
// pubShares from EncryptedPartialDecryptionSubmitted events (cb-mpc 34 bytes):
//   pid=1 (0xC6cB...): 043f9b2c51ac1fdceb81fd70ac94c3d190d7419a9a0098cefd28e1cbae4dd1490efb
//   pid=3 (0xc8AE...): 043f9f885c9be9517f0ca2ffe83e8396079e4f5c4c801b586c8eb9462f84887a0264

func TestLiveNetworkKeyConsistency(t *testing.T) {
	c, err := curve.NewEd25519()
	require.NoError(t, err)
	defer c.Free()

	// On-chain global pub key (prepend 043f for cb-mpc)
	globalPubHex := "043f" + "ee293ab357ebe7775d1038a0f6e88987b3ea96a66d201b2dde850016542d5141"
	globalPubBytes, _ := hex.DecodeString(globalPubHex)

	Qglobal, err := curve.NewPointFromBytes(globalPubBytes)
	require.NoError(t, err, "failed to parse global pub key")
	defer Qglobal.Free()

	// pubShare for pid=1 (index=1, Kyber party 0, eval point 1)
	ps1Hex := "043f9b2c51ac1fdceb81fd70ac94c3d190d7419a9a0098cefd28e1cbae4dd1490efb"
	ps1Bytes, _ := hex.DecodeString(ps1Hex)
	Q1, err := curve.NewPointFromBytes(ps1Bytes)
	require.NoError(t, err, "failed to parse pubShare1")
	defer Q1.Free()

	// pubShare for pid=3 (index=3, Kyber party 2, eval point 3)
	ps3Hex := "043f9f885c9be9517f0ca2ffe83e8396079e4f5c4c801b586c8eb9462f84887a0264"
	ps3Bytes, _ := hex.DecodeString(ps3Hex)
	Q3, err := curve.NewPointFromBytes(ps3Bytes)
	require.NoError(t, err, "failed to parse pubShare3")
	defer Q3.Free()

	t.Logf("Qglobal: %s", hex.EncodeToString(Qglobal.Bytes()))
	t.Logf("Q1 (pid=1): %s", hex.EncodeToString(Q1.Bytes()))
	t.Logf("Q3 (pid=3): %s", hex.EncodeToString(Q3.Bytes()))

	// Ed25519 group order
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	// Lagrange coefficients for pids=[1, 3], threshold=2:
	//   L_1(0) = (0-3)/(1-3) = -3/-2 = 3/2 mod l
	//   L_3(0) = (0-1)/(3-1) = -1/2 mod l
	halfInv := new(big.Int).ModInverse(big.NewInt(2), l)

	L1 := new(big.Int).Mul(big.NewInt(3), halfInv)
	L1.Mod(L1, l)

	L3 := new(big.Int).Neg(halfInv)
	L3.Mod(L3, l)

	L1bytes := make([]byte, 32)
	copy(L1bytes[32-len(L1.Bytes()):], L1.Bytes())

	L3bytes := make([]byte, 32)
	copy(L3bytes[32-len(L3.Bytes()):], L3.Bytes())

	t.Logf("L_1(0) = %s", L1.Text(16))
	t.Logf("L_3(0) = %s", L3.Text(16))

	// Q_recon = L_1(0) * Q1 + L_3(0) * Q3
	term1, err := Q1.Multiply(&curve.Scalar{Bytes: L1bytes})
	require.NoError(t, err)
	defer term1.Free()

	term3, err := Q3.Multiply(&curve.Scalar{Bytes: L3bytes})
	require.NoError(t, err)
	defer term3.Free()

	Qrecon := term1.Add(term3)
	defer Qrecon.Free()

	t.Logf("Qrecon: %s", hex.EncodeToString(Qrecon.Bytes()))
	t.Logf("Qglobal: %s", hex.EncodeToString(Qglobal.Bytes()))

	if Qrecon.Equals(Qglobal) {
		t.Log("MATCH: pubShares reconstruct the global key correctly")
		t.Log("The DKG shares ARE consistent — look elsewhere for the combine bug")
	} else {
		t.Log("MISMATCH: pubShares DO NOT reconstruct the global key")
		t.Log("Possible causes:")
		t.Log("  1. PIDs don't match Kyber evaluation points (index ordering issue)")
		t.Log("  2. Global key on-chain is from a different DKG round than the shares")
		t.Log("  3. DKG protocol produced inconsistent shares")

		// Try with swapped PIDs to check ordering
		t.Log("\nTrying with swapped PID assignment...")

		// What if Q1 is actually at eval point 3, Q3 at eval point 1?
		L1swap := new(big.Int).Neg(halfInv)
		L1swap.Mod(L1swap, l)
		L3swap := new(big.Int).Mul(big.NewInt(3), halfInv)
		L3swap.Mod(L3swap, l)

		L1swapBytes := make([]byte, 32)
		copy(L1swapBytes[32-len(L1swap.Bytes()):], L1swap.Bytes())
		L3swapBytes := make([]byte, 32)
		copy(L3swapBytes[32-len(L3swap.Bytes()):], L3swap.Bytes())

		t1, _ := Q1.Multiply(&curve.Scalar{Bytes: L1swapBytes})
		defer t1.Free()
		t3, _ := Q3.Multiply(&curve.Scalar{Bytes: L3swapBytes})
		defer t3.Free()
		Qswap := t1.Add(t3)
		defer Qswap.Free()

		t.Logf("Qswap: %s", hex.EncodeToString(Qswap.Bytes()))
		if Qswap.Equals(Qglobal) {
			t.Error("MATCH WITH SWAPPED PIDs! The PID assignment is REVERSED")
			t.Error("Q1's pubShare has eval point 3, Q3's pubShare has eval point 1")
			t.Error("This means the PIDCache returns the wrong PID for the validator")
		}

		// Brute force all 2-element subsets from eval points 1..5
		t.Log("\nBrute-forcing all PID pairs [1..5]...")
		for p1 := 1; p1 <= 5; p1++ {
			for p3 := 1; p3 <= 5; p3++ {
				if p1 == p3 {
					continue
				}
				// L_p1(0) = -p3 / (p1-p3)
				// L_p3(0) = -p1 / (p3-p1)
				denom1 := new(big.Int).SetInt64(int64(p1 - p3))
				denom1.Mod(denom1, l)
				inv1 := new(big.Int).ModInverse(denom1, l)
				Lp1 := new(big.Int).Mul(big.NewInt(int64(-p3)), inv1)
				Lp1.Mod(Lp1, l)

				denom3 := new(big.Int).SetInt64(int64(p3 - p1))
				denom3.Mod(denom3, l)
				inv3 := new(big.Int).ModInverse(denom3, l)
				Lp3 := new(big.Int).Mul(big.NewInt(int64(-p1)), inv3)
				Lp3.Mod(Lp3, l)

				Lp1b := make([]byte, 32)
				copy(Lp1b[32-len(Lp1.Bytes()):], Lp1.Bytes())
				Lp3b := make([]byte, 32)
				copy(Lp3b[32-len(Lp3.Bytes()):], Lp3.Bytes())

				tt1, _ := Q1.Multiply(&curve.Scalar{Bytes: Lp1b})
				tt3, _ := Q3.Multiply(&curve.Scalar{Bytes: Lp3b})
				Qtest := tt1.Add(tt3)

				if Qtest.Equals(Qglobal) {
					t.Errorf("FOUND MATCH: Q1 at eval_point=%d, Q3 at eval_point=%d", p1, p3)
					t.Errorf("  Expected: Q1 at 1, Q3 at 3")
					t.Errorf("  This means the PID→eval_point mapping is WRONG")
				}

				Qtest.Free()
				tt1.Free()
				tt3.Free()
			}
		}
	}
}
