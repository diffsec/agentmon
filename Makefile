.PHONY: build build-shim test lint clean proto ebpf
.PHONY: smoke ptrace-test dns-test seccomp-probe bench
.PHONY: completions package-snapshot package-release
.PHONY: build-macos-enterprise build-macos-go build-swift assemble-bundle sign-bundle
.PHONY: build-macwrap

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
GOPATH ?= $(CURDIR)/.gopath

build:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh ./cmd/agentsh
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-shell-shim ./cmd/agentsh-shell-shim
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-unixwrap ./cmd/agentsh-unixwrap

build-shim:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-shell-shim ./cmd/agentsh-shell-shim

# Build macwrap (requires macOS with Xcode - uses cgo for darwin-specific code)
build-macwrap:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOOS=darwin CGO_ENABLED=1 GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-macwrap ./cmd/agentsh-macwrap

proto:
	protoc -I proto \
	  --go_out=. --go_opt=module=github.com/agentsh/agentsh \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/agentsh/agentsh \
	  proto/agentsh/v1/pty.proto

test:
	mkdir -p $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go test ./...

smoke:
	bash scripts/smoke.sh

ptrace-test:
	docker build -f Dockerfile.ptrace-test -t agentsh-ptrace-test .
	docker run --rm --cap-add SYS_PTRACE agentsh-ptrace-test

dns-test:
	docker build -f Dockerfile.dns-test -t agentsh-dns-test .
	docker run --rm --cap-add SYS_PTRACE agentsh-dns-test

seccomp-probe:
	mkdir -p build
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/seccomp-probe ./cmd/seccomp-probe/

bench:
	bash scripts/bench-modes.sh

lint:
	@echo "No linter configured"

clean:
	rm -rf bin build coverage.out dist

# Rebuild eBPF objects from source (requires clang and Linux BTF headers)
ebpf:
	$(MAKE) -C internal/netmonitor/ebpf clean all

# Generate shell completions
completions: build
	mkdir -p packaging/completions
	bin/agentsh completion bash > packaging/completions/agentsh.bash
	bin/agentsh completion zsh > packaging/completions/agentsh.zsh
	bin/agentsh completion fish > packaging/completions/agentsh.fish

# Build packages locally using goreleaser (snapshot mode, no publish)
package-snapshot: completions
	goreleaser release --snapshot --clean --skip=publish

# Build release packages (requires GITHUB_TOKEN, usually run by CI)
package-release:
	goreleaser release --clean

# =============================================================================
# macOS Enterprise Build (System Extension + Network Extension)
# NOTE: build-macos-go, build-swift, assemble-bundle, and sign-bundle require macOS with Xcode
# =============================================================================

# Build the Go binaries that ship in the app bundle. agentsh needs CGO for
# system extension support (nofuse: no macFUSE headers required), matching
# the release pipeline's rebuild.
build-macos-go:
	rm -rf build/go-local
	mkdir -p build/go-local
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -tags nofuse $(LDFLAGS) -o build/go-local/agentsh ./cmd/agentsh
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o build/go-local/agentsh-shell-shim ./cmd/agentsh-shell-shim
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o build/go-local/agentsh-stub ./cmd/agentsh-stub

# Build Swift components via Xcode (requires macOS with Xcode)
build-swift:
	xcodebuild \
		-project macos/AgentSH/agentsh.xcodeproj \
		-scheme agentsh \
		-configuration Release \
		-derivedDataPath build/DerivedData \
		CODE_SIGN_IDENTITY="" \
		CODE_SIGNING_REQUIRED=NO \
		CODE_SIGNING_ALLOWED=NO

# Assemble app bundle (shared logic: scripts/assemble-macos-bundle.sh)
assemble-bundle: build-macos-go build-swift
	GO_BIN_DIR=build/go-local scripts/assemble-macos-bundle.sh build/AgentSH.app

# Sign bundle (requires SIGNING_IDENTITY env var; shared logic:
# scripts/sign-macos-bundle.sh)
sign-bundle:
	scripts/sign-macos-bundle.sh build/AgentSH.app

# Full enterprise build, gated on provisioning-profile verification (#440)
build-macos-enterprise: assemble-bundle sign-bundle
	scripts/verify-macos-bundle.sh build/AgentSH.app
	@echo "Enterprise build complete: build/AgentSH.app"
