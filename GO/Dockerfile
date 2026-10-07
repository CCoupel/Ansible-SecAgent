# secagent-server — image de production (build deterministe, BORE).
#
# Les images de base sont epinglees par DIGEST (mises a jour par Dependabot, package-ecosystem docker).
# Le runtime n'utilise aucun `apk add` : pas de dependance a un depot de paquets flottant, donc pas de
# derive entre deux builds du meme tag. Les certificats racine viennent de l'image de build epinglee.

# ---- Build -------------------------------------------------------------------------------------
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Pur Go, sans CGO (l'etat du relay est un fichier, plus de SQLite : v3.0.3).
# -trimpath et -buildvcs=false : le binaire ne depend ni du chemin de build ni de l'etat git.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o secagent-server ./cmd/secagent-server

# ---- Runtime -----------------------------------------------------------------------------------
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/secagent-server /app/secagent-server

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
