# secagent-server — image de production (build deterministe, BORE).
#
# Les images de base sont epinglees par DIGEST (mises a jour par Dependabot, package-ecosystem docker).
# Le runtime n'utilise aucun `apk add` : pas de dependance a un depot de paquets flottant, donc pas de
# derive entre deux builds du meme tag. Les certificats racine viennent de l'image de build epinglee.

# ---- Build -------------------------------------------------------------------------------------
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version affichee par `secagent-server --version` : `dev` par defaut (builds locaux et CI), la release passe
# `--build-arg VERSION=X.Y.Z` (release.yml). Constante par tag : le build reste deterministe.
ARG VERSION=dev

# Pur Go, sans CGO (l'etat du relay est un fichier, plus de SQLite : v3.0.3).
# -trimpath et -buildvcs=false : le binaire ne depend ni du chemin de build ni de l'etat git.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X secagent-server/cmd/secagent-server/internal/cli.Version=${VERSION}" -o secagent-server ./cmd/secagent-server

# ---- Runtime -----------------------------------------------------------------------------------
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/secagent-server /app/secagent-server
# Licence AGPL-3.0-or-later et mentions tierces des modules lies (#237) : copies suivies dans GO/ (contexte de build),
# gardees identiques aux originaux de la racine par scripts/ci/gen_third_party_notices.sh --check (job lint).
COPY LICENSE THIRD_PARTY_NOTICES.md /app/

# Utilisateur non-root, UID/GID FIXES : le meme sur tous les hotes, car STATE_DIR est un partage
# (NFS) dont les droits sont portes par l'UID numerique (voir DEPLOYMENT/prod/README.md).
RUN addgroup -g 10001 -S relay && adduser -S -u 10001 -G relay -H -s /sbin/nologin relay \
    && mkdir -p /data /run/secagent && chown relay:relay /data /run/secagent
USER 10001:10001

ENV STATE_DIR=/data \
    RELAY_STATUS_FILE=/run/secagent/status.json

# Sonde = `secagent-server status --local` (#163) : lit le statut ecrit par le process lui-meme, sans
# ouvrir de connexion ; un secondaire (aucun port ouvert) est donc `healthy`, un process fige passe
# `unhealthy`. Plus de sonde HTTP : le TLS est natif (#175) et les ports 7770/7772 n'existent pas
# sur un secondaire.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/app/secagent-server", "status", "--local"]

# 7770 API REST + WS relays, 7771 admin (ne JAMAIS publier hors boucle locale / reseau d'admin),
# 7772 WebSocket des agents.
EXPOSE 7770 7771 7772

ENTRYPOINT ["/app/secagent-server"]
