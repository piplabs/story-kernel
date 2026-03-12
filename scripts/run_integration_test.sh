#!/usr/bin/env bash
set -euo pipefail

# Ensure Go is on PATH (commonly missing after re-login on some systems).
if ! command -v go &>/dev/null; then
  echo "[integration-test] 'go' not found, adding /usr/local/go/bin to PATH..."
  export PATH="$PATH:/usr/local/go/bin"
  if ! grep -qF '/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
  if ! command -v go &>/dev/null; then
    echo "[integration-test] ERROR: 'go' still not found after adding /usr/local/go/bin. Please check your Go installation." >&2
    exit 1
  fi
fi

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
gramine-manifest -D bin_name=integration-test -D log_level=error \
  story-kernel.manifest.template integration-test.manifest
sed -i 's/enclave_size = "1G"/enclave_size = "4G"/' integration-test.manifest

echo "[integration-test] Signing manifest..."
gramine-sgx-sign --manifest integration-test.manifest \
  --output integration-test.manifest.sgx

echo "[integration-test] Running: ${TEST_FILTER}"
gramine-sgx integration-test -test.v -test.run "${TEST_FILTER}"