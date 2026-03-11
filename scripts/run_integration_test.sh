#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CBMPC_PATH="${CBMPC_PATH:-.cbmpc}"
TEST_FILTER="${1:-TestDKGHappyPath_3Nodes}"

cd "${REPO_ROOT}"

echo "[integration-test] Building test binary..."
CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh "${CBMPC_PATH}" \
  go test -c -v ./integration/ \
  -o ./build/integration-test

echo "[integration-test] Generating Gramine manifest..."
gramine-manifest -D bin_name=integration-test \
  story-kernel.manifest.template integration-test.manifest
sed -i 's/enclave_size = "1G"/enclave_size = "4G"/' integration-test.manifest

echo "[integration-test] Signing manifest..."
gramine-sgx-sign --manifest integration-test.manifest \
  --output integration-test.manifest.sgx

echo "[integration-test] Running: ${TEST_FILTER}"
gramine-sgx integration-test -test.v -test.run "${TEST_FILTER}"
