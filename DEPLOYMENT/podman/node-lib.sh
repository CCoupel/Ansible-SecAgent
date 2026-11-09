# shellcheck shell=bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Bibliotheque (SOURCEE, jamais executee seule) de stage-node-files.sh et verify-node-files.sh (#267, LOT-4) :
# topologie des noeuds Podman, liste des fichiers de deploiement d'un noeud et generation DETERMINISTE de son unite
# systemd --user. Le contenu attendu d'un noeud se recalcule donc toujours depuis le depot (source de confiance).
# Exige : refuse(), REPO, PRIVATE_DIR definis par l'appelant.
# shellcheck disable=SC2034   # ENV, NODE_IP... sont lues par les scripts qui sourcent cette bibliotheque

# $1 env, $2 noeud -> variables ENV (QUALIF|PROD), NODE_IP, PROJECT_NAME, NODE_SERVICES, COMPOSE_ARGS, SOURCES
# (fichiers du depot copies tels quels dans release/, chemin source:nom).
node_topology() {
  case "$1:$2" in
    qualif:srv3) ENV=QUALIF; NODE_IP=192.168.1.213; NODE_SERVICES="secagent-server-a" ;;
    qualif:srv4) ENV=QUALIF; NODE_IP=192.168.1.214; NODE_SERVICES="secagent-server-b secagent-child minion-root minion-child" ;;
    prod:srv1) ENV=PROD; NODE_IP=192.168.1.211; NODE_SERVICES="secagent-server" ;;
    prod:srv2) ENV=PROD; NODE_IP=192.168.1.212; NODE_SERVICES="secagent-server" ;;
    *) refuse "couple '$1 $2' : attendu qualif srv3|srv4 ou prod srv1|srv2" ;;
  esac
  if [ "$1" = qualif ]; then
    PROJECT_NAME=secagent-qualif
    COMPOSE_ARGS="-f docker-compose.chain.yml -f docker-compose.hooks.yml -f docker-compose.podman.qualif.yml"
    SOURCES="DEPLOYMENT/qualif/docker-compose.chain.yml DEPLOYMENT/qualif/docker-compose.server.yml DEPLOYMENT/qualif/docker-compose.hooks.yml DEPLOYMENT/podman/docker-compose.podman.qualif.yml"
  else
    PROJECT_NAME=secagent-prod
    COMPOSE_ARGS="-f docker-compose.server.yml -f docker-compose.podman.yml"
    SOURCES="DEPLOYMENT/prod/docker-compose.server.yml DEPLOYMENT/podman/docker-compose.podman.yml"
  fi
  NODE_BASE="$PRIVATE_DIR/$ENV/$2/cyril/secagent"
  UNIT_NAME="secagent-$1-$2.service"
}

# Variables NON secretes ecrites dans release/release.env (lues par l'unite au demarrage) : liste FERMEE.
RELEASE_ENV_VARS="SECAGENT_IMAGE SECAGENT_MINION_IMAGE SECAGENT_VERSION SECAGENT_PULL_POLICY SECAGENT_MEM_LIMIT GOMEMLIMIT LOG_LEVEL"
# release.env attendu, deterministe : variables de la liste presentes dans l'environnement + chemins du partage.
# Refus si une valeur contient un caractere hors [A-Za-z0-9_.:/@=+-] (pas d'espace, de saut de ligne ni de guillemet).
release_env() { # $1 env, $2 noeud (node_topology deja appele)
  local v
  for v in $RELEASE_ENV_VARS; do
    [ -n "${!v:-}" ] || continue
    [[ ${!v} =~ ^[A-Za-z0-9_.:/@=+-]+$ ]] || refuse "$v='${!v}' : caracteres non autorises dans release.env"
    printf '%s=%s\n' "$v" "${!v}"
  done
  if [ "$1" = qualif ]; then
    printf 'QUALIF_PRIVATE_DIR=%s\nQUALIF_TLS_DIR=%s\nQUALIF_NODE_A_ADDR=%s\nCHAIN_DIR=%s\n' \
      "$PRIVATE_DIR/QUALIF" "$PRIVATE_DIR/QUALIF/pki" 192.168.1.213 "$PRIVATE_DIR/QUALIF/srv4/cyril/secagent/run"
  else
    printf 'STATE_HOST_DIR=%s\nSECRETS_DIR=%s\nTLS_CERT_DIR=%s\n' \
      "$PRIVATE_DIR/PROD/state/root" "$PRIVATE_DIR/PROD/secrets" "$PRIVATE_DIR/PROD/pki"
  fi
}

# Unite --user du noeud (liee par `systemctl --user link`, jamais copiee sur le noeud). Deterministe.
node_unit() { # $1 env, $2 noeud (node_topology deja appele)
  cat <<EOF
# Genere par DEPLOYMENT/podman/stage-node-files.sh (#267) : conteneurs secagent $1 du noeud $2 (Podman rootless).
# Liee depuis le partage : partage absent = unite absente (fail-closed) ; garde check-private.sh avant tout demarrage.
[Unit]
Description=secagent $1 ($2) : conteneurs Podman rootless
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=3

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$NODE_BASE/release
EnvironmentFile=$NODE_BASE/release/release.env
ExecStartPre=$NODE_BASE/bin/check-private.sh $1 $2
ExecStart=/usr/bin/podman-compose -p $PROJECT_NAME $COMPOSE_ARGS up -d $NODE_SERVICES
ExecStop=/usr/bin/podman-compose -p $PROJECT_NAME $COMPOSE_ARGS stop $NODE_SERVICES
Restart=on-failure
RestartSec=30
TimeoutStartSec=600

[Install]
WantedBy=default.target
EOF
}

# Manifeste ATTENDU "sha256  sous-dossier/nom" (release/ et systemd/), recalcule depuis le depot dans $1 (repertoire
# temporaire de l'appelant) : copies des sources, release.env et unite generes.
expected_tree() { # $1 repertoire de sortie, $2 env, $3 noeud
  local out="$1" f
  mkdir -p "$out/release" "$out/systemd"
  # NODE_SOURCE_DIR (optionnel) : repertoire extrait d'une archive de release (Compose dont l'image est reecrite en
  # tag@digest) ; les fichiers y sont pris par leur nom. Sinon : le depot.
  local src
  for f in $SOURCES; do
    if [ -n "${NODE_SOURCE_DIR:-}" ]; then src="$NODE_SOURCE_DIR/$(basename "$f")"; else src="$REPO/$f"; fi
    [ -f "$src" ] && [ ! -L "$src" ] || refuse "$src absent ou lien"
    cp "$src" "$out/release/$(basename "$f")"
  done
  release_env "$2" "$3" > "$out/release/release.env"
  node_unit "$2" "$3" > "$out/systemd/$UNIT_NAME"
  ( cd "$out/release" && sha256sum -- * > SHA256SUMS )
  ( cd "$out/systemd" && sha256sum -- * > SHA256SUMS )
}
