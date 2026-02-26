#!/usr/bin/env bash

set -e

if ! which buf 1>/dev/null; then
  echo "buf not found, please install: https://buf.build/docs/installation"
  exit 1
fi

echo "buf version: $(buf --version)"

# Lint proto files
buf lint proto

# Clean generated files
rm -f ./types/*.pb.go 2>/dev/null || true

# Generate proto files (same as make proto-gen)
cd proto && buf dep update && buf build && buf generate && cd -
