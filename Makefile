# CyberMind Makefile
VERSION := $(shell cat VERSION)

.PHONY: all build build-linux build-windows backend-install clean help

all: build

## Build CLI for current OS
build:
	@echo "Building CyberMind CLI v$(VERSION)..."
	@cd cli && go build -ldflags="-X main.Version=$(VERSION)" -o cybermind .
	@echo "✓ Built: cli/cybermind"

## Build for Kali Linux / Linux amd64
build-linux:
	@echo "Building for Linux amd64..."
	@cd cli && GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o cybermind-linux-amd64 .
	@echo "✓ Built: cli/cybermind-linux-amd64"

## Build for Windows amd64
build-windows:
	@echo "Building for Windows amd64..."
	@cd cli && GOOS=windows GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o cybermind-windows-amd64.exe .
	@echo "✓ Built: cli/cybermind-windows-amd64.exe"

## Build all platforms
build-all: build-linux build-windows
	@echo "✓ All builds complete"

## Install backend dependencies
backend-install:
	@echo "Installing backend dependencies..."
	@cd backend && npm install
	@echo "✓ Backend ready"

## Install CLI globally on Linux/Kali
install: build-linux
	@sudo mv cli/cybermind-linux-amd64 /usr/local/bin/cybermind
	@echo "✓ Installed to /usr/local/bin/cybermind"
	@echo "  Run: cybermind"

## Start backend
backend:
	@cd backend && node src/app.js

## Clean build artifacts
clean:
	@rm -f cli/cybermind cli/cybermind-linux-amd64 cli/cybermind-windows-amd64.exe
	@echo "✓ Cleaned"

## Show help
help:
	@echo ""
	@echo "  CyberMind v$(VERSION) — Build Commands"
	@echo "  ─────────────────────────────────────"
	@echo "  make build          Build for current OS"
	@echo "  make build-linux    Build for Kali/Linux"
	@echo "  make build-windows  Build for Windows"
	@echo "  make build-all      Build all platforms"
	@echo "  make install        Install to /usr/local/bin"
	@echo "  make backend        Start backend server"
	@echo "  make backend-install Install npm deps"
	@echo "  make clean          Remove build artifacts"
	@echo ""
