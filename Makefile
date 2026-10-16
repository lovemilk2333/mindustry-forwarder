# mindustry-forwarder build entry
#
# Builds the Go decoder (server side). The Python encoder needs no build step.
#
# Usage:
#   make                        build amd64 decoder (default)
#   make decoder-amd64          -> bin/decoder/amd64/mindustry-forwarder-decoder
#   make decoder-arm64          -> bin/decoder/arm64/mindustry-forwarder-decoder
#                               (zig cross-compile, glibc 2.31)
#   make decoder                build both architectures
#   make DEBUG=1 decoder-amd64  build with debug info (-gcflags=all=-N -l)
#   make clean                  remove bin/

SHELL := /usr/bin/env bash

BIN_DIR := bin/decoder
DECODER_NAME := mindustry-forwarder-decoder
DECODER_DIR := decoder
# Build the whole cmd package so //go:embed (setup-lo script) is included.
DECODER_PKG := ./cmd

# ---- version info ---------------------------------------------------------

COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u -Iseconds)
LDFLAGS_VARS := -X 'main.CommitHash=$(COMMIT_HASH)' -X 'main.BuildTime=$(BUILD_TIME)'

ifdef DEBUG
GO_BUILD_FLAGS := -gcflags=all=-N -l
BASE_LDFLAGS := $(LDFLAGS_VARS)
else
GO_BUILD_FLAGS := -trimpath
BASE_LDFLAGS := -s -w $(LDFLAGS_VARS)
endif

# zig cc cross-compiles to glibc 2.31 for the device (its glibc is older
# than the dev machine's).
ZIG := $(HOME)/tools/zig/zig
ZIG_TARGET := aarch64-linux-gnu.2.31

# ---- targets --------------------------------------------------------------

.PHONY: all decoder decoder-amd64 decoder-arm64 clean help

all: decoder-amd64 decoder-arm64

help:
	@echo "targets:"
	@echo "  decoder-amd64   $(BIN_DIR)/amd64/$(DECODER_NAME)"
	@echo "  decoder-arm64   $(BIN_DIR)/arm64/$(DECODER_NAME)  (zig $(ZIG_TARGET))"
	@echo "  decoder         both architectures"
	@echo "  clean           remove bin/"
	@echo "  DEBUG=1         disable strip, keep debug symbols"

decoder: decoder-amd64 decoder-arm64

decoder-amd64:
	mkdir -p $(BIN_DIR)/amd64
	cd $(DECODER_DIR) && \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GO_BUILD_FLAGS) \
			-ldflags "$(BASE_LDFLAGS)" \
			-o ../$(BIN_DIR)/amd64/$(DECODER_NAME) \
			$(DECODER_PKG)
	@echo "built $(BIN_DIR)/amd64/$(DECODER_NAME)"

# arm64: link against glibc 2.31 via zig so the binary runs on the stick.
# CGO is required for IP_TRANSPARENT (syscall) builds that need a C linker
# when using -linkmode external; zig provides the old-glibc toolchain.
decoder-arm64:
	mkdir -p $(BIN_DIR)/arm64
	@test -x "$(ZIG)" || { echo "error: zig not found at $(ZIG)"; exit 1; }
	cd $(DECODER_DIR) && \
		CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
		CC="$(ZIG) cc -target $(ZIG_TARGET)" \
		go build $(GO_BUILD_FLAGS) \
			-ldflags "$(BASE_LDFLAGS) -linkmode external" \
			-o ../$(BIN_DIR)/arm64/$(DECODER_NAME) \
			$(DECODER_PKG)
	@echo "built $(BIN_DIR)/arm64/$(DECODER_NAME)"

clean:
	rm -rf bin
