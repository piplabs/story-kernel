#!/usr/bin/env bash

set -e

# Runs go test for all touched packages
if [ -z "$*" ]; then
  echo "No Go files changed, skipping tests"
  exit 0
fi

MOD=$(go list -m)
PKGS=$(echo "$@" | xargs -n1 dirname | sort -u | sed -e "s#^#${MOD}/#")

# Ensure cb-mpc is available (same as make setup-cbmpc)
make -s setup-cbmpc

# Use go_with_cpp.sh to set up CGO environment properly (matches make test)
CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh .cbmpc go test -failfast -timeout=5m $PKGS
