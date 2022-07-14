MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := ci

.DELETE_ON_ERROR:
.SUFFIXES:

BINDIR=_bin

GO=GCO_ENABLED=0 go
GOFLAGS := -ldflags '-w -s' -trimpath

GODEPS=$(shell find . -name "*.go")
DEPS=$(GODEPS) go.mod go.sum

VERSION := 0.1.0

CTR ?= podman

GOLANGCI_LINT ?= $(BINDIR)/tools/golangci-lint

.PHONY: build
build: $(BINDIR)/shack

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	@rm -rf $(BINDIR)

.PHONY: ci
ci: tools test vet fmt golangci-lint binaries

.PHONY: vet
vet:
	@echo "+ $@"
	@$(GO) vet cmd/shack/main.go

.PHONY: fmt
fmt:
	@echo "+ $@"
	@if [[ ! -z "$(shell gofmt -l -s . | grep -v vendor | tee /dev/stderr)" ]]; then exit 1; fi

.PHONY: golangci-lint
golangci-lint: | $(BINDIR)/tools/golangci-lint
	@echo "+ $@"
	@$(GOLANGCI_LINT) run

.PHONY: binaries
binaries: $(BINDIR)/shack $(BINDIR)/shack-linux-amd64

.PHONY: binaries-ctr
binaries-ctr:
	$(CTR) run -it --rm -v $(shell pwd)/:/usr/src/shack -w /usr/src/shack docker.io/library/golang:1.18-stretch make binaries

$(BINDIR) $(BINDIR)/tools $(BINDIR)/downloaded:
	@mkdir -p $@

$(BINDIR)/shack: $(DEPS) | $(BINDIR)
	$(GO) build $(GOFLAGS) -o $@ cmd/shack/main.go

$(BINDIR)/shack-linux-amd64: $(DEPS) | $(BINDIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $@ cmd/shack/main.go

.PHONY: container
container:
	$(CTR) build -t shack:latest -f Containerfile .
	$(CTR) tag shack:latest quay.io/adjetstack/shack:latest

.PHONY: container-push
container-push:
	$(CTR) push quay.io/adjetstack/shack:latest

.PHONY: curlpine-container-push
curlpine-container-push:
	$(CTR) build -t curlpine:latest -f hack/Containerfile.curlpine .
	$(CTR) tag curlpine:latest quay.io/adjetstack/curlpine:latest
	$(CTR) push quay.io/adjetstack/curlpine:latest

.PHONY: tools
tools: $(BINDIR)/tools/golangci-lint $(BINDIR)/tools/mkcert

GOLANGCI_LINT_VERSION=v1.46.2
MKCERT_VERSION=1.4.4

$(BINDIR)/tools/golangci-lint: $(BINDIR)/downloaded/golangci-lint@$(GOLANGCI_LINT_VERSION)| $(BINDIR)/tools
	ln -f $< $@

$(BINDIR)/downloaded/golangci-lint@$(GOLANGCI_LINT_VERSION): | $(BINDIR)/downloaded
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv $(BINDIR)/downloaded/golangci-lint $@

$(BINDIR)/tools/mkcert: $(BINDIR)/downloaded/mkcert@$(MKCERT_VERSION) | $(BINDIR)/tools
	ln -f $< $@
	chmod +x $@

$(BINDIR)/downloaded/mkcert@$(MKCERT_VERSION): | $(BINDIR)/downloaded
	curl -sSL --retry 5 -o $@ https://github.com/FiloSottile/mkcert/releases/download/v$(MKCERT_VERSION)/mkcert-v$(MKCERT_VERSION)-linux-amd64

.PHONY: localcert
localcert: | $(BINDIR)/tools/mkcert
	CAROOT=$(BINDIR) $(BINDIR)/tools/mkcert -cert-file $(BINDIR)/cert.pem -key-file $(BINDIR)/key.pem -ecdsa localhost tls-v1-2.badssl.com go.dev speed.hetzner.de
