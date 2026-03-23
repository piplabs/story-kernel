#!/usr/bin/env bash
# P1 Integration Tests — Production reliability: idempotency, fault tolerance, cheating, input validation, resharing.
# Continues on failure and prints a summary at the end.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CBMPC_PATH="${CBMPC_PATH:-.cbmpc}"

cd "${REPO_ROOT}"

# ── Ensure binary and manifest are ready ────────────────────────────
if [[ ! -f build/integration-test ]]; then
  echo "[runner] Binary not found. Building..."
  CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh "${CBMPC_PATH}" \
    go test -c -v ./integration/ -o ./build/integration-test
fi

if [[ ! -f integration-test.manifest.sgx ]]; then
  echo "[runner] Manifest not found. Generating and signing..."
  gramine-manifest -D bin_name=integration-test -D log_level=error \
    story-kernel.manifest.template integration-test.manifest
  sed -i 's/enclave_size = "1G"/enclave_size = "8G"/' integration-test.manifest
  gramine-sgx-sign --manifest integration-test.manifest \
    --output integration-test.manifest.sgx
fi

# ── P1 test list ─────────────────────────────────────────────────────
P1_CASES=(
  # DKG happy path
  "TestDKGHappyPath_ReRegisterAfterAllRegistered"
  "TestDKGHappyPath_Idempotent"
  # TDH2 decrypt
  "TestTDH2_AllCombinations"
  "TestTDH2_WrongLabel"
  "TestTDH2_WrongGlobalPubKey"
  # TDH2 signature verification (PR #18 review)
  "TestTDH2_PartialDecryptSignatureValid"
  "TestTDH2_TamperedResponseFailsSignatureVerification"
  # Fault tolerance
  "TestFaultTolerance_PartialDecryptNodeUnavailable"
  "TestFaultTolerance_NodeRestartCanStillDecrypt"
  # Cheating detection
  "TestCheatingDetection_TamperedDeal"
  "TestCheatingDetection_TamperedDealAllNodes"
  "TestCheatingDetection_DuplicateDeal"
  "TestCheatingDetection_CrossRoundReplay"
  "TestCheatingDetection_PartialDealSkip_ValidDealsStillPersist"
  # Persistence
  "TestPersistence_AllNodesRestart"
  "TestPersistence_MultipleSequentialRestarts"
  # Error validation — input validation
  "TestErrorValidation_ZeroRound"
  "TestErrorValidation_EmptyCodeCommitment"
  "TestErrorValidation_EmptyAddress"
  "TestErrorValidation_EmptyCiphertext"
  "TestErrorValidation_InvalidRequesterPubKey"
  "TestErrorValidation_MissingRequesterPubKey"
  "TestErrorValidation_RoundMismatchPartialDecrypt"
  "TestErrorValidation_FinalizeDKGZeroRound"
  "TestErrorValidation_FinalizeDKGEmptyCodeCommitment"
  # Resharing
  "TestResharing_PubKeySharesDiffer"
  "TestResharing_AllCombinationsAfterResharing"
  "TestResharing_ProcessResponses_SurvivesMissingPrevDKG"
  "TestResharing_ScaleDown_3To2"
  "TestResharing_ScaleUp_3To5"
  "TestResharing_ZeroOverlap"
  "TestResharing_MidCrashDuringGenerateDeals"
  # Process justification — real complaint flow
  "TestProcessJustification_RealComplaintFlow"
  "TestProcessJustification_PersistenceAfterRestart"
  # Concurrent RPC
  "TestConcurrent_PartialDecryptSameNode"
  "TestConcurrent_PartialDecryptAllNodes"
  "TestConcurrent_GenerateDealsAllNodes"
  "TestConcurrent_ProcessDealsAllNodes"
  # Out-of-order DKG call sequences
  "TestOutOfOrder_FinalizeDKG_SkipProcessResponses"
  "TestOutOfOrder_FinalizeDKG_SkipProcessDealsAndResponses"
  "TestOutOfOrder_PartialDecrypt_BeforeFinalizeDKG"
  # Mid-DKG restart
  "TestMidDKGRestart_AfterProcessDeals"
  # Multi-round DKG
  "TestMultiRound_ThreeSequentialRounds"
  "TestRoundBoundary_FutureRoundRejected"
  # Round boundary & cache isolation
  "TestRoundCtxCache_StaleCacheUsesOldRegistrations"
  # QueryClient data inconsistency
  "TestQueryInconsistency_RegistrationCountLessThanTotal"
  "TestQueryInconsistency_DuplicateRegistrationIndex"
  "TestQueryInconsistency_ThresholdExceedsTotal"
  "TestQueryInconsistency_ZeroThreshold"
  "TestQueryInconsistency_RegistrationCountMoreThanTotal"
  "TestQueryInconsistency_RoundMismatch"
  "TestQueryInconsistency_DuplicateIndex_PropagatesThroughDKG"
  # gRPC transport layer
  "TestGRPC_HappyPath_EndToEnd"
  "TestGRPC_ErrorCodeMapping"
  "TestGRPC_LargePayload"
  "TestGRPC_ConcurrentClients"
  # Upgrade & version compatibility
  "TestUpgrade_DKGStateExtraFieldsIgnored"
  "TestUpgrade_DKGStateMinimalFieldsLoadable"
  "TestUpgrade_DistKeyShareMarshalRoundtrip"
  # Security review — defense in depth (S-series)
  "TestResharing_FlagAbuse_TrueOnInitialRound"
  "TestResharing_FlagAbuse_FalseOnResharingRound"
  "TestResharing_FlagAbuse_FinalizeMismatch"
  "TestCheatingDetection_DealIndexOutOfBounds"
  "TestCheatingDetection_AllDealsInvalid_Rejected"
)

# ── Runner ───────────────────────────────────────────────────────────
PASS_CASES=()
FAIL_CASES=()

run_test() {
  local name="$1"
  echo ""
  echo "============================================================"
  echo "[RUNNING] ${name}"
  echo "============================================================"

  local tmp_log
  tmp_log=$(mktemp /tmp/sk-test-XXXXXX.log)

  gramine-sgx integration-test -test.v -test.run "^${name}$" 2>&1 | tee "${tmp_log}"
  local pipe_exit="${PIPESTATUS[0]}"

  if grep -qE "^--- FAIL:|^FAIL$" "${tmp_log}" || [[ "${pipe_exit}" -ne 0 ]]; then
    FAIL_CASES+=("${name}")
    echo ""
    echo ">>> [FAIL] ${name}"
  else
    PASS_CASES+=("${name}")
    echo ""
    echo ">>> [PASS] ${name}"
  fi

  rm -f "${tmp_log}"
}

for case_name in "${P1_CASES[@]}"; do
  run_test "${case_name}"
done

# ── Summary ──────────────────────────────────────────────────────────
total=$(( ${#PASS_CASES[@]} + ${#FAIL_CASES[@]} ))
echo ""
echo "============================================================"
echo "SUMMARY (P1)  Total: ${total} | PASS: ${#PASS_CASES[@]} | FAIL: ${#FAIL_CASES[@]}"
echo "============================================================"
for c in "${PASS_CASES[@]}"; do echo "  [PASS] ${c}"; done
for c in "${FAIL_CASES[@]}"; do echo "  [FAIL] ${c}"; done
echo "============================================================"

[[ ${#FAIL_CASES[@]} -eq 0 ]]
