#!/usr/bin/env bash
# Run ALL integration tests — build, generate SGX manifest, and execute every test case.
# Continues on failure and prints a summary at the end.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CBMPC_PATH="${CBMPC_PATH:-.cbmpc}"

cd "${REPO_ROOT}"

# ── Build integration test binary ────────────────────────────────────
echo "============================================================"
echo "[build] Compiling integration test binary..."
echo "============================================================"
CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh "${CBMPC_PATH}" \
  go test -c -v ./integration/ -o ./build/integration-test

if [[ ! -f build/integration-test ]]; then
  echo "[build] FATAL: build/integration-test not found after compilation."
  exit 1
fi
echo "[build] Binary ready: build/integration-test"

# ── Generate and sign Gramine SGX manifest ───────────────────────────
echo ""
echo "============================================================"
echo "[manifest] Generating and signing SGX manifest..."
echo "============================================================"
gramine-manifest -D bin_name=integration-test -D log_level=error \
  story-kernel.manifest.template integration-test.manifest
sed -i 's/enclave_size = "1G"/enclave_size = "8G"/' integration-test.manifest
gramine-sgx-sign --manifest integration-test.manifest \
  --output integration-test.manifest.sgx
echo "[manifest] SGX manifest ready."

# ── All test cases ───────────────────────────────────────────────────
ALL_CASES=(
  # ── P0: Security boundary, core DKG/TDH2, critical fault tolerance ──
  # DKG happy path
  "TestDKGHappyPath_3Nodes"
  # TDH2 decrypt
  "TestTDH2_PartialDecryptAndCombine"
  "TestTDH2_ThresholdNotMet"
  # Fault tolerance
  "TestFaultTolerance_OneNodeDown"
  "TestFaultTolerance_TwoNodesDown"
  # Persistence
  "TestPersistence_RestartRecovery"
  # Error validation — security boundary
  "TestErrorValidation_WrongCodeCommitment"
  "TestErrorValidation_PartialDecrypt_PIDNotCached"
  "TestErrorValidation_WrongCodeCommitment_GenerateDeals"
  "TestErrorValidation_WrongCodeCommitment_ProcessDeals"
  "TestErrorValidation_WrongCodeCommitment_FinalizeDKG"
  "TestErrorValidation_WrongCodeCommitment_ProcessResponses"
  "TestErrorValidation_WrongCodeCommitment_PartialDecryptTDH2"
  "TestErrorValidation_ProcessJustification_WrongCodeCommitment"
  # Resharing
  "TestResharing_KeyRotation"
  "TestResharing_NewCommitteeCannotGenerateDeals"
  # Mid-DKG restart
  "TestMidDKGRestart_BeforeFinalizeDKG"
  # Round boundary
  "TestRoundBoundary_OldRoundRejectedAfterResharing"
  # Code commitment
  "TestGetCodeCommitment_ReturnsValidCommitment"
  # QueryClient error injection
  "TestQueryError_GetDKGNetwork_GenerateAndSealKey"
  "TestQueryError_GetRegistrations_GenerateAndSealKey"
  "TestQueryError_VerifyStartBlock_GenerateAndSealKey"
  "TestQueryError_GetDKGNetwork_GenerateDeals"
  "TestQueryError_GetDKGNetwork_ProcessDeals"
  "TestQueryError_GetLatestActiveNetwork_PartialDecrypt"
  # HasDecryptRequest validation
  "TestErrorValidation_DecryptRequestNotExist"
  "TestQueryError_HasDecryptRequest_PartialDecrypt"
  "TestQueryError_GetRegistrations_FinalizeDKG"
  "TestQueryError_GetDKGNetwork_ProcessResponses"
  "TestQueryError_GetRegistrations_GenerateDeals"
  "TestQueryError_TransientError_RecoveryAfterClear"
  # Resharing QueryClient error injection
  "TestQueryError_Resharing_GetLatestActiveNetwork_GenerateDeals"
  "TestQueryError_Resharing_GetLatestActiveNetwork_ProcessResponses"
  "TestQueryError_Resharing_GetLatestActiveNetwork_ProcessJustification"
  "TestQueryError_Resharing_GetLatestActiveNetwork_ProcessDeals"
  "TestQueryError_Resharing_GetRegistrations_FetchLatestPubKeysAndCoeffs"

  # ── P1: Production reliability ─────────────────────────────────────
  # DKG happy path
  "TestDKGHappyPath_ReRegisterAfterAllRegistered"
  "TestDKGHappyPath_Idempotent"
  # TDH2 decrypt
  "TestTDH2_AllCombinations"
  "TestTDH2_WrongLabel"
  "TestTDH2_WrongGlobalPubKey"
  # TDH2 signature verification
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
  # Process justification
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

  # ── P2: Robustness — edge cases & secondary validation ─────────────
  # Error validation — secondary input checks
  "TestErrorValidation_GenerateDealsZeroRound"
  "TestErrorValidation_ProcessDealsEmptyDeals"
  "TestErrorValidation_ProcessJustification_ZeroRound"
  "TestErrorValidation_ProcessJustification_EmptyCodeCommitment"
  "TestErrorValidation_ProcessJustification_EmptyJustifications"
  "TestErrorValidation_ProcessResponsesEmptyResponses"
  "TestErrorValidation_EmptyLabel"
  "TestErrorValidation_EmptyGlobalPubKey"
  # TDH2 signature — property checks
  "TestTDH2_SignatureNonEmpty"
  "TestTDH2_SignatureConsistentAcrossNodes"
  "TestTDH2_SignatureBindsCiphertext"
  # Code commitment — metadata & edge cases
  "TestGetCodeCommitment_Is32Bytes"
  "TestGetCodeCommitment_ConsistentAcrossNodes"
  "TestGetCodeCommitment_NoInputRequired"
  "TestGetCodeCommitment_RepeatedCallsConsistent"
  # Process justification — false-pass tests
  "TestProcessJustification_InvalidJustification_SilentlySkipped"
  "TestProcessJustification_Resharing_InvalidJustification_SilentlySkipped"
  "TestProcessJustification_MultipleInvalidJustifications_SilentlySkipped"
  "TestProcessJustification_InvalidJustification_AllNodes_SilentlySkipped"
  # Concurrent RPC
  "TestConcurrent_MultipleRequesters"
  # MockQueryClient semantic constraints
  "TestMockQC_PerRoundNetworkOverride"
  "TestMockQC_PerRoundErrorPrecedence"
  "TestMockQC_PerRoundRegistrationOverride"
  "TestMockQC_FallbackToDefaultNetwork"
  # Out-of-order DKG call sequences
  "TestOutOfOrder_GenerateDeals_Repeated"
  "TestOutOfOrder_ProcessResponses_BeforeProcessDeals"
  "TestOutOfOrder_ProcessDeals_AfterFinalizeDKG"
  # TDH2 boundary conditions
  "TestErrorValidation_TruncatedCiphertext"
  "TestErrorValidation_MismatchedLabel"
  "TestErrorValidation_InvalidPID_Zero"
  "TestErrorValidation_InvalidPID_OutOfRange"
  # Persistence — robustness
  "TestPersistence_SealedKeysSurviveCleanup"
  "TestPersistence_CorruptedSealedFile"
  # Security review — characterization & defense in depth (S-series)
  "TestTDH2_RepeatedDecryptSameCiphertext"
  "TestTDH2_DifferentRequestersSameCiphertext"
  "TestOutOfOrder_FinalizeDKG_CalledTwice"
  "TestErrorValidation_PartialDecrypt_CrossRoundShareInjection"
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

for case_name in "${ALL_CASES[@]}"; do
  run_test "${case_name}"
done

# ── Summary ──────────────────────────────────────────────────────────
total=$(( ${#PASS_CASES[@]} + ${#FAIL_CASES[@]} ))
echo ""
echo "============================================================"
echo "SUMMARY (ALL)  Total: ${total} | PASS: ${#PASS_CASES[@]} | FAIL: ${#FAIL_CASES[@]}"
echo "============================================================"
for c in "${PASS_CASES[@]}"; do echo "  [PASS] ${c}"; done
for c in "${FAIL_CASES[@]}"; do echo "  [FAIL] ${c}"; done
echo "============================================================"

[[ ${#FAIL_CASES[@]} -eq 0 ]]
