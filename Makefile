export GO111MODULE = on

GO ?= go

build_tags := $(strip $(BUILD_TAGS))
BUILD_FLAGS := -tags "$(build_tags)"

OUT_DIR = ./build
BIN_NAME = story-kernel

# cb-mpc settings
CBMPC_DIR = .cbmpc
CBMPC_REPO = https://github.com/piplabs/cb-mpc.git
CBMPC_COMMIT = 7f03db8a8fa1
CBMPC_PATH = $(CBMPC_DIR)

PROTO_DIR=proto
PROTOBUF_DIR=types
PROTO_OUT_DIR=./

.PHONY: build build-with-cpp clean proto-gen test integration-test run setup-deps \
        gramine-manifest gramine-sign gramine-enclave-info all-gramine \
        setup-cbmpc lint

# Clone and build cb-mpc if not present
setup-cbmpc:
	@if [ ! -d "$(CBMPC_DIR)" ]; then \
		echo "Cloning cb-mpc..."; \
		git lfs install --skip-smudge 2>/dev/null || true; \
		git clone $(CBMPC_REPO) $(CBMPC_DIR); \
		cd $(CBMPC_DIR) && git checkout $(CBMPC_COMMIT); \
	fi
	@if [ ! -f "$(CBMPC_DIR)/lib/Release/libcbmpc.dylib" ] && [ ! -f "$(CBMPC_DIR)/lib/Release/libcbmpc.so" ]; then \
		echo "Building cb-mpc C++ library (dynamic)..."; \
		mkdir -p $(CBMPC_DIR)/build; \
		cd $(CBMPC_DIR)/build && \
		cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_SHARED_LIBS=ON && \
		make -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4); \
	fi

# Simple build without cb-mpc (requires pre-built libcbmpc.a)
build:
	$(GO) build -mod=readonly $(BUILD_FLAGS) -o $(OUT_DIR)/$(BIN_NAME) ./

# Build with cb-mpc C++ library (auto-builds cb-mpc if needed)
build-with-cpp: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) $(GO) build -mod=readonly $(BUILD_FLAGS) -ldflags="-extldflags=-Wl,-w" -o $(OUT_DIR)/$(BIN_NAME) ./

# Run standard (non-SGX) binary
run:
	$(OUT_DIR)/$(BIN_NAME) $(ARGS)

# ============ Gramine SGX Support ============
# Gramine can run unmodified binaries with full OpenSSL 3.x support

# Generate Gramine manifest from template
gramine-manifest: build-with-cpp
	gramine-manifest \
		-Dlog_level=error \
		-Dbin_name=$(BIN_NAME) \
		story-kernel.manifest.template > story-kernel.manifest

# Sign for Gramine SGX
gramine-sign: gramine-manifest
	gramine-sgx-sign \
		--manifest story-kernel.manifest \
		--output story-kernel.manifest.sgx

gramine-enclave-info:
	@echo "Code Commitment: $(shell gramine-sgx-sigstruct-view story-kernel.sig | grep mr_enclave)"

# Build + sign for Gramine
all-gramine: gramine-sign
	@echo "Gramine build complete."
	@make gramine-enclave-info
	@echo "Run with: gramine-sgx story-kernel $(ARGS)"

clean:
	$(GO) clean
	rm -rf $(OUT_DIR)
	rm -f story-kernel.manifest story-kernel.manifest.sgx story-kernel.sig

clean-all: clean
	rm -rf $(CBMPC_DIR)

proto-gen:
	rm -f $(PROTO_OUT_DIR)$(PROTOBUF_DIR)/*.pb.go
	cd $(PROTO_DIR) && buf dep update && buf build && buf generate; cd -

test: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -v ./...

integration-test: setup-cbmpc
	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) go test -v -count=1 ./integration/...

# Install dependencies for Ubuntu (run with sudo)
setup-deps:
	@echo "Installing build dependencies..."
	apt-get update
	apt-get install -y build-essential cmake libssl-dev
	@echo ""
	@echo "For Gramine/SGX support, see: https://gramine.readthedocs.io/en/stable/installation.html"

# ============ Linting Support ============
# CGO environment required for golangci-lint to avoid buildssa errors

lint: setup-cbmpc
	CGO_ENABLED=1 CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh $(CBMPC_PATH) golangci-lint run --timeout 10m
