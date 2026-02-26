#!/usr/bin/env bash

set -e

# Runs go test for all touched packages
if [ -z "$*" ]; then
  echo "No Go files changed, skipping tests"
  exit 0
fi

MOD=$(go list -m)
PKGS=$(echo "$@" | xargs -n1 dirname | sort -u | sed -e "s#^#${MOD}/#")

# Use go_with_cpp.sh to set up CGO environment properly
CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh .cbmpc go test -failfast -race -timeout=5m $PKGS
