BINARY  := scopeward
PKG     := github.com/sunnysystems/scopeward
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/cli.version=$(VERSION)

.PHONY: build test vet fmt lint clean install

build: ## Build the binary into ./scopeward
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/scopeward

install: ## Install into GOBIN
	go install -ldflags "$(LDFLAGS)" ./cmd/scopeward

test: ## Run tests with the race detector
	go test -race ./...

vet:
	go vet ./...

fmt: ## Check formatting
	@test -z "$$(gofmt -l internal cmd)" || (gofmt -l internal cmd; exit 1)

clean:
	rm -f $(BINARY)
