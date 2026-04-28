APP_NAME := host-cmd-bridge
PKG := ./cmd/agent
DIST_DIR := dist
BIN_DIR := $(DIST_DIR)/bin
PKG_DIR := $(DIST_DIR)/packages

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo nogit)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

GOCACHE_DIR ?= $(CURDIR)/.cache/go-build
GOMODCACHE_DIR ?= $(CURDIR)/.cache/go-mod

LDFLAGS := -s -w \
	-X 'host-cmd-bridge/internal/version.Version=$(VERSION)' \
	-X 'host-cmd-bridge/internal/version.Commit=$(COMMIT)' \
	-X 'host-cmd-bridge/internal/version.BuildTime=$(BUILD_TIME)'

.PHONY: test build build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-all package clean

test:
	mkdir -p $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) go test ./...

build:
	mkdir -p $(BIN_DIR) $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) $(PKG)

build-linux-amd64:
	mkdir -p $(BIN_DIR) $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOOS=linux GOARCH=amd64 GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 $(PKG)

build-linux-arm64:
	mkdir -p $(BIN_DIR) $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOOS=linux GOARCH=arm64 GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-linux-arm64 $(PKG)

build-darwin-amd64:
	mkdir -p $(BIN_DIR) $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOOS=darwin GOARCH=amd64 GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-darwin-amd64 $(PKG)

build-darwin-arm64:
	mkdir -p $(BIN_DIR) $(GOCACHE_DIR) $(GOMODCACHE_DIR)
	GOOS=darwin GOARCH=arm64 GOCACHE=$(GOCACHE_DIR) GOMODCACHE=$(GOMODCACHE_DIR) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME)-darwin-arm64 $(PKG)

build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

package:
	mkdir -p $(PKG_DIR)
	./scripts/package.sh $(VERSION)

clean:
	rm -rf $(DIST_DIR)

