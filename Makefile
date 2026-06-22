export GO111MODULE = on

GO ?= go

build_tags := $(strip $(BUILD_TAGS))
BUILD_FLAGS := -tags "$(build_tags)"

OUT_DIR = ./build
BIN_NAME = story-kernel

# Build info injected via -ldflags -X
GIT_COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
GIT_TIMESTAMP := $(shell git log -1 --format=%cI 2>/dev/null || echo "unknown")
BUILDINFO_PKG := github.com/piplabs/story-kernel/buildinfo
BUILDINFO_FLAGS := -X $(BUILDINFO_PKG).GitCommit=$(GIT_COMMIT) -X $(BUILDINFO_PKG).GitTimestamp=$(GIT_TIMESTAMP)

# cb-mpc settings
CBMPC_DIR = .cbmpc
CBMPC_REPO = https://github.com/piplabs/cb-mpc-fork.git
CBMPC_COMMIT = v0.0.1-alpha
CBMPC_PATH = $(CBMPC_DIR)

PROTO_DIR=proto
PROTOBUF_DIR=types
PROTO_OUT_DIR=./

.PHONY: build build-sgx build-tdx clean proto-gen test test-cover test-noop \
        test-tdx run setup-deps gramine-manifest gramine-sign \
        gramine-enclave-info all-sgx all-tdx setup-cbmpc lint lint-noop lint-tdx

# Clone cb-mpc if not present; the C++ build is handled by go_with_cpp.sh
setup-cbmpc:
	@if [ ! -d "$(CBMPC_DIR)" ]; then \
		echo "Cloning cb-mpc..."; \
		git lfs install --skip-smudge 2>/dev/null || true; \
		git clone $(CBMPC_REPO) $(CBMPC_DIR); \
		cd $(CBMPC_DIR) && git checkout $(CBMPC_COMMIT); \
	fi

# build (untagged) — local development with the noop TEE backend.
# Produces a binary that fail-closes on every TEE operation. Do NOT use for
# devnet, mainnet, or any environment that performs DKG.
build: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) $(GO) build -mod=readonly $(BUILD_FLAGS) -ldflags="-buildid= $(BUILDINFO_FLAGS) -extldflags=-Wl,-w" -o $(OUT_DIR)/$(BIN_NAME) ./

# build-sgx — production SGX/Gramine build with cb-mpc C++ library.
# mr_enclave-stable across rebuilds.
build-sgx: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) $(GO) build -mod=readonly -tags "sgx $(build_tags)" -ldflags="-buildid= $(BUILDINFO_FLAGS) -extldflags=-Wl,-w" -o $(OUT_DIR)/$(BIN_NAME) ./

# build-tdx — production TDX build with cb-mpc C++ library. CGO/cb-mpc
# setup is identical to the SGX target.
build-tdx: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) $(GO) build -mod=readonly -tags "tdx $(build_tags)" -ldflags="-buildid= $(BUILDINFO_FLAGS) -extldflags=-Wl,-w" -o $(OUT_DIR)/$(BIN_NAME) ./

# Run standard (non-SGX) binary
run:
	$(OUT_DIR)/$(BIN_NAME) $(ARGS)

# ============ Gramine SGX Support ============
# Gramine can run unmodified binaries with full OpenSSL 3.x support

# Generate Gramine manifest from template
gramine-manifest: build-sgx
	gramine-manifest \
		story-kernel.manifest.template > story-kernel.manifest

# Sign for Gramine SGX
gramine-sign: gramine-manifest
	gramine-sgx-sign \
		--manifest story-kernel.manifest \
		--output story-kernel.manifest.sgx

gramine-enclave-info:
	@echo "Code Commitment: $(shell gramine-sgx-sigstruct-view story-kernel.sig | grep mr_enclave)"

# all-sgx — full SGX/Gramine deploy-ready pipeline: build + sign + show MRENCLAVE.
all-sgx: gramine-sign
	@echo "SGX/Gramine build complete."
	@make gramine-enclave-info
	@echo "Run with: gramine-sgx story-kernel $(ARGS)"

# all-tdx — full TDX deploy-ready pipeline: build + operator notes.
# No on-host signing step (TDX has no Gramine equivalent); deployment
# concerns (vTPM, dm-crypt, image build) live outside this repo.
all-tdx: build-tdx
	@echo "TDX build complete."
	@echo "Run with: $(OUT_DIR)/$(BIN_NAME) $(ARGS)"
	@echo ""
	@echo "First-run note: bootstrap mode logs the measured PCR digest."
	@echo "Paste it into supportedProviders[].ExpectedDigest in"
	@echo "enclave/tdx/providers.go, rebuild, and redeploy for strict mode."

clean:
	$(GO) clean
	rm -rf $(OUT_DIR)
	rm -f story-kernel.manifest story-kernel.manifest.sgx story-kernel.sig

clean-all: clean
	rm -rf $(CBMPC_DIR)

proto-gen:
	rm -f $(PROTO_OUT_DIR)$(PROTOBUF_DIR)/*.pb.go
	cd $(PROTO_DIR) && buf dep update && buf build && buf generate; cd -

# test — run unit tests under the SGX backend (production path).
test: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -tags sgx -v ./...

# test-cover — coverage run under the SGX backend.
test-cover: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -tags sgx -coverprofile=coverage.txt -timeout=5m -race ./...

# test-noop — exercise the package-level shim and noop fail-closed paths.
# No SGX hardware required; useful as a fast pre-merge gate.
test-noop: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -timeout=5m ./...

# test-tdx — exercise the TDX backend with the TPM2 simulator and a mock
# quote provider. No TDX silicon required; the simulator is a Go module and
# bootstraps inside test code.
test-tdx: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -tags tdx -timeout=5m ./...

# Install dependencies for Ubuntu (run with sudo)
setup-deps:
	@echo "Installing build dependencies..."
	apt-get update
	apt-get install -y build-essential cmake libssl-dev
	@echo ""
	@echo "For Gramine/SGX support, see: https://gramine.readthedocs.io/en/stable/installation.html"

# ============ Linting Support ============
# CGO environment required for golangci-lint to avoid buildssa errors

# lint — production SGX-tagged lint.
lint: setup-cbmpc
	CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) golangci-lint run --build-tags=sgx --timeout 10m

# lint-noop — lint the untagged (noop) build so the shim layer stays clean.
lint-noop: setup-cbmpc
	CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) golangci-lint run --timeout 10m

# lint-tdx — lint the TDX-tagged tree so tag-isolated regressions are caught.
lint-tdx: setup-cbmpc
	CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) golangci-lint run --build-tags=tdx --timeout 10m
