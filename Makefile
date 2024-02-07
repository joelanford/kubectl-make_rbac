SHELL:=/bin/bash
.DEFAULT_GOAL := install

export GIT_VERSION = $(shell git describe --tags --always)
export GIT_COMMIT = $(shell git rev-parse HEAD)
export GIT_COMMIT_TIME = $(shell TZ=UTC git show -s --format=%cd --date=format-local:%Y-%m-%dT%TZ)
export GIT_TREE_STATE = $(shell sh -c '(test -n "$(shell git status -s)" && echo "dirty") || echo "clean"')
export CGO_ENABLED = 1

# bingo manages consistent tooling versions for things like kind, kustomize, etc.
include .bingo/Variables.mk

REPO = $(shell go list -m)
PROJECT = $(shell basename $(REPO))
GO_BUILD_ARGS = \
  -gcflags "all=-trimpath=$(shell dirname $(shell pwd))" \
  -asmflags "all=-trimpath=$(shell dirname $(shell pwd))" \
  -ldflags " \
    -s \
    -w \
    -X '$(REPO)/internal/version.GitVersion=$(GIT_VERSION)' \
    -X '$(REPO)/internal/version.GitCommit=$(GIT_COMMIT)' \
    -X '$(REPO)/internal/version.GitCommitTime=$(GIT_COMMIT_TIME)' \
    -X '$(REPO)/internal/version.GitTreeState=$(GIT_TREE_STATE)' \
  " \

.PHONY: clean
clean:
	rm -rf bin

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: build
build: vet fmt
	go build $(GO_BUILD_ARGS) -o bin/$(PROJECT)

.PHONY: test
test:
	go test ./...

.PHONY: install
install: build
	install bin/$(PROJECT) $(shell go env GOPATH)/bin

.PHONY: lint
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run $(GOLANGCI_LINT_ARGS)

.PHONY: release
RELEASE_ARGS = --clean --snapshot
release: $(GORELEASER)
	 $(GORELEASER) $(RELEASE_ARGS)
