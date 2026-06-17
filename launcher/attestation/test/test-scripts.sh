#!/bin/bash
# test-scripts.sh — host-side entry point. Runs run-in-container.sh inside
# a one-shot Ubuntu container with swtpm + tpm2-tools, so the test works
# without those packages installed on the host.
#
# Usage:
#   ./test-scripts.sh
#
# Exit 0 on full pass; non-zero on any failure.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPTS_DIR=$(cd "$HERE/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
    echo "test-scripts: docker required (skipping)"
    exit 0
fi

# Mount the scripts dir read-only at /work; run the in-container orchestrator.
exec docker run --rm \
    -v "$SCRIPTS_DIR":/work:ro \
    -e SCRIPTS_DIR=/work \
    ubuntu:24.04 \
    /bin/bash /work/test/run-in-container.sh
