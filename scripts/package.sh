#!/usr/bin/env bash
set -euo pipefail
export COPYFILE_DISABLE=1

APP_NAME="host-cmd-bridge"
PKG="./cmd/agent"
VERSION="${1:-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PKG_DIR="$DIST_DIR/packages"
TMP_DIR="$DIST_DIR/.tmp"
GOCACHE_DIR="$ROOT_DIR/.cache/go-build"
GOMODCACHE_DIR="$ROOT_DIR/.cache/go-mod"

LDFLAGS="-s -w -X host-cmd-bridge/internal/version.Version=${VERSION} -X host-cmd-bridge/internal/version.Commit=${COMMIT} -X host-cmd-bridge/internal/version.BuildTime=${BUILD_TIME}"

mkdir -p "$PKG_DIR" "$TMP_DIR" "$GOCACHE_DIR" "$GOMODCACHE_DIR"

SKILL_SRC="$ROOT_DIR/skills/hostcmd-bridge-client"
if [[ ! -d "$SKILL_SRC" ]]; then
  echo "[error] skill source not found: $SKILL_SRC" >&2
  exit 1
fi

MATRIX=(
  "linux amd64"
  "linux arm64"
)

for item in "${MATRIX[@]}"; do
  read -r GOOS GOARCH <<<"$item"
  PKG_ROOT="${APP_NAME}-${GOOS}-${GOARCH}"
  STAGE_DIR="$TMP_DIR/${PKG_ROOT}"
  PKG_ROOT_DIR="$STAGE_DIR/$PKG_ROOT"
  rm -rf "$STAGE_DIR"
  mkdir -p "$PKG_ROOT_DIR/containerskill/host-cmd-bridge"

  BIN_NAME="$APP_NAME"
  if [[ "$GOOS" == "windows" ]]; then
    BIN_NAME="${APP_NAME}.exe"
  fi

  echo "[build] ${GOOS}/${GOARCH}"
  (
    cd "$ROOT_DIR"
    GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    GOCACHE="$GOCACHE_DIR" GOMODCACHE="$GOMODCACHE_DIR" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$PKG_ROOT_DIR/$BIN_NAME" "$PKG"
  )

  cp -R "$SKILL_SRC"/. "$PKG_ROOT_DIR/containerskill/host-cmd-bridge/"
  chmod +x "$PKG_ROOT_DIR/containerskill/host-cmd-bridge/scripts/"*
  cp "$ROOT_DIR/config.example.yaml" "$PKG_ROOT_DIR/"
  cp "$ROOT_DIR/policy.example.yaml" "$PKG_ROOT_DIR/"

  # Remove common macOS metadata files from staging.
  find "$PKG_ROOT_DIR" -type f \( -name ".DS_Store" -o -name "._*" \) -delete

  ARCHIVE="${APP_NAME}-${GOOS}-${GOARCH}.tar.gz"
  tar -C "$STAGE_DIR" -czf "$PKG_DIR/$ARCHIVE" "$PKG_ROOT"
  echo "[package] $PKG_DIR/$ARCHIVE"
done

(
  cd "$PKG_DIR"
  shasum -a 256 *.tar.gz > SHA256SUMS
  echo "[package] $PKG_DIR/SHA256SUMS"
)
