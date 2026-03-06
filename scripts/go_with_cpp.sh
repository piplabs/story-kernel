#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Path to the public cb-mpc repository (e.g. sibling directory)
CBMPC_REPO="${CBMPC_REPO:-https://github.com/piplabs/cb-mpc.git}"
CBMPC_ROOT_ARG="${1:-}"
if [[ -n "${CBMPC_ROOT_ARG}" ]]; then
  if [[ -d "${CBMPC_ROOT_ARG}" ]]; then
    CBMPC_ROOT="$(cd "${CBMPC_ROOT_ARG}" && pwd)"
    shift
  else
    echo "[go_with_cpp] Provided cb-mpc path does not exist: ${CBMPC_ROOT_ARG}" >&2
    exit 1
  fi
else
  CBMPC_ROOT="${CBMPC_ROOT:-${REPO_ROOT}/../cb-mpc}"
  if [[ ! -d "${CBMPC_ROOT}" ]]; then
    echo "[go_with_cpp] Cloning public cb-mpc from ${CBMPC_REPO} into ${CBMPC_ROOT}"
    mkdir -p "$(dirname "${CBMPC_ROOT}")"
    git clone "${CBMPC_REPO}" "${CBMPC_ROOT}"
  fi
  CBMPC_ROOT="$(cd "${CBMPC_ROOT}" && pwd)"
fi

BUILD_TYPE="${BUILD_TYPE:-Release}"

# Auto-detect OpenSSL location if not set
if [[ -z "${CBMPC_OPENSSL_ROOT:-}" ]]; then
  # For Linux, check common system locations (prefer dynamic libs)
  if [[ "$(uname -s)" != "Darwin" ]]; then
    # First try system OpenSSL (Ubuntu/Debian)
    if [[ -f "/usr/lib/x86_64-linux-gnu/libcrypto.so" ]]; then
      export CBMPC_OPENSSL_ROOT="/usr"
      export CBMPC_OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"
      echo "[go_with_cpp] Auto-detected system OpenSSL (dynamic)"
    # Fallback to static if available
    elif [[ -f "/usr/lib/x86_64-linux-gnu/libcrypto.a" ]]; then
      export CBMPC_OPENSSL_ROOT="/usr"
      export CBMPC_OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"
      echo "[go_with_cpp] Auto-detected system OpenSSL (static)"
    elif [[ -f "/usr/local/lib64/libcrypto.a" ]]; then
      export CBMPC_OPENSSL_ROOT="/usr/local"
      export CBMPC_OPENSSL_LIB_DIR="/usr/local/lib64"
      echo "[go_with_cpp] Auto-detected OpenSSL in /usr/local"
    fi
  # For macOS, use Homebrew
  elif command -v brew >/dev/null 2>&1; then
    DETECTED_OPENSSL="$(brew --prefix openssl@3 2>/dev/null || true)"
    if [[ -n "${DETECTED_OPENSSL}" && -d "${DETECTED_OPENSSL}" ]]; then
      export CBMPC_OPENSSL_ROOT="${DETECTED_OPENSSL}"
      echo "[go_with_cpp] Auto-detected Homebrew OpenSSL: ${CBMPC_OPENSSL_ROOT}"
    fi
  fi
fi

# cb-mpc source directory
INC_DIR="${CBMPC_ROOT}/src"

# Auto-build cb-mpc library if needed (BEFORE setting up library paths)
if [[ -f "${CBMPC_ROOT}/scripts/auto_build_cpp.sh" ]]; then
  bash "${CBMPC_ROOT}/scripts/auto_build_cpp.sh"
fi

# Set up library paths AFTER build directories exist
LIB_DIRS=(
  "${CBMPC_ROOT}/build/${BUILD_TYPE}/lib"
  "${CBMPC_ROOT}/lib/${BUILD_TYPE}"
)

LDFLAGS_ACCUM=()
for d in "${LIB_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    LDFLAGS_ACCUM+=("-L${d}")
  fi
done

# Add OpenSSL include path to CGO flags if available
CFLAGS_ACCUM="-I${INC_DIR}"
if [[ -n "${CBMPC_OPENSSL_ROOT:-}" ]]; then
  CFLAGS_ACCUM="${CFLAGS_ACCUM} -I${CBMPC_OPENSSL_ROOT}/include"
  # Use specific lib dir if set, otherwise try common locations
  if [[ -n "${CBMPC_OPENSSL_LIB_DIR:-}" ]]; then
    LDFLAGS_ACCUM+=("-L${CBMPC_OPENSSL_LIB_DIR}")
  elif [[ -d "${CBMPC_OPENSSL_ROOT}/lib64" ]]; then
    LDFLAGS_ACCUM+=("-L${CBMPC_OPENSSL_ROOT}/lib64")
  elif [[ -d "${CBMPC_OPENSSL_ROOT}/lib" ]]; then
    LDFLAGS_ACCUM+=("-L${CBMPC_OPENSSL_ROOT}/lib")
  fi
fi

# Add -rpath for dynamic library runtime loading
for d in "${LIB_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    LDFLAGS_ACCUM+=("-Wl,-rpath,${d}")
  fi
done

# Link against cb-mpc library
if [[ "$(uname -s)" == "Darwin" ]]; then
  # On macOS, link statically to avoid dyld symbol resolution issues
  # caused by -fvisibility=hidden in the shared library build.
  STATIC_LIB=""
  for d in "${LIB_DIRS[@]}"; do
    if [[ -f "${d}/libcbmpc.a" ]]; then
      STATIC_LIB="${d}/libcbmpc.a"
      break
    fi
  done
  if [[ -n "${STATIC_LIB}" ]]; then
    LDFLAGS_ACCUM+=("${STATIC_LIB}" "-lc++")
  else
    LDFLAGS_ACCUM+=("-lcbmpc")
    LDFLAGS_ACCUM+=("-Wl,-flat_namespace" "-Wl,-undefined,suppress")
  fi
else
  LDFLAGS_ACCUM+=("-lcbmpc")
  LDFLAGS_ACCUM+=("-Wl,--allow-multiple-definition")
  LDFLAGS_ACCUM+=("-static-libstdc++" "-static-libgcc")
fi

export CGO_CFLAGS="${CFLAGS_ACCUM}"
export CGO_CXXFLAGS="${CFLAGS_ACCUM}"
export CGO_LDFLAGS="${LDFLAGS_ACCUM[*]}"
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-tags=gofuzz"
export BUILD_TYPE

echo "[go_with_cpp] CGO_CFLAGS: ${CGO_CFLAGS}"
echo "[go_with_cpp] CGO_LDFLAGS: ${CGO_LDFLAGS}"

cd "${REPO_ROOT}"

# Inject reproducible build flags for SGX code commitment determinism
# Without these, builds on different machines produce different binaries
if [[ "${1:-}" == *go && "${2:-}" == "build" ]]; then
  REPRO_FLAGS=(-trimpath -buildvcs=false -ldflags="-buildid=")
  echo "[go_with_cpp] Adding reproducible build flags: ${REPRO_FLAGS[*]}"
  set -- "$1" "$2" "${REPRO_FLAGS[@]}" "${@:3}"
fi

exec "$@"
