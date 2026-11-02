# Raccourcis de developpement (#224). La reference reste scripts/ci.sh (commands.ci, contrat C11) : la CI ne passe
# PAS par ce Makefile pour ses controles bloquants ; `make ci` l'appelle tel quel. Les images sont construites par
# GO/Dockerfile et GO/Dockerfile.agent (release.yml), jamais ici.
#
#   make build              les trois binaires dans ./build (CGO_ENABLED=0, comme les images)
#   make secagent-server    un seul binaire (idem secagent-minion, secagent-inventory)
#   make test               tests du module (-race : CGO requis, comme la CI)
#   make lint               gofmt + golangci-lint (v2.14.0 en CI)
#   make ci                 scripts/ci.sh (build, build sans CGO, tests -race, gofmt, golangci-lint)

BUILD_DIR := ./build
BINARIES  := secagent-server secagent-minion secagent-inventory
VERSION   ?= dev
LDFLAGS_secagent-server := -s -w -X secagent-server/cmd/secagent-server/internal/cli.Version=$(VERSION)
LDFLAGS_secagent-minion := -s -w -X main.Version=$(VERSION)
LDFLAGS_secagent-inventory := -s -w

.PHONY: build $(BINARIES) test lint ci clean help

build: $(BINARIES)

$(BINARIES):
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS_$@)" -o $(BUILD_DIR)/$@ ./cmd/$@

test:
	JWT_SECRET_KEY=test ADMIN_TOKEN=test go test -race ./... -timeout 300s

lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "Fichiers non conformes a gofmt :"; echo "$$out"; exit 1; fi
	golangci-lint run --timeout=5m

ci:
	bash ../scripts/ci.sh

clean:
	rm -rf $(BUILD_DIR)

help:
	@sed -n '1,9p' Makefile
