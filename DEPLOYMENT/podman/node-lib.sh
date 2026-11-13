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
  # PRIVATE_DIR est ecrit tel quel dans l'unite et release.env : memes caracteres permis que les autres valeurs.
  [[ $PRIVATE_DIR =~ ^/[A-Za-z0-9_./-]+$ && ! /$PRIVATE_DIR/ =~ /\.\./ ]] || refuse "SECAGENT_PRIVATE_DIR='$PRIVATE_DIR' : chemin absolu [A-Za-z0-9_./-] sans .. attendu"
  case "$1:$2" in
    qualif:srv3) ENV=QUALIF; NODE_IP=192.168.1.213; NODE_SERVICES="secagent-server-a" ;;
    # Unite = racine SEULEMENT (a sur srv3, b sur srv4) : seul chemin de creation/demarrage de a et b (boot, Restart=,
    # chain-test.sh root_up). L'enfant et les minions de QUALIF sont des services de TEST, crees et demarres par
    # chain-test.sh seulement (bootstrap) : jamais par l'unite (pas de double chemin pour un meme service, T48).
    qualif:srv4) ENV=QUALIF; NODE_IP=192.168.1.214; NODE_SERVICES="secagent-server-b" ;;
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
  # Manifeste EPINGLE sur le noeud, HORS partage (home local de cyril) : ecrit par `verify-node-files.sh --pin` apres une
  # verification reussie contre le depot, relu par ExecStartPre a CHAQUE demarrage (reboot, Restart=, relance manuelle).
  PIN_REL=".config/secagent/$1-$2.sha256"
  # Copie locale (hors partage) de l'unite, ecrite par `verify-node-files.sh --pin` : c'est elle que systemd charge.
  UNIT_REL=".config/systemd/user/$UNIT_NAME"
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
    # SECAGENT_TMPFS_OPTS=U : proprietaire des tmpfs sous Podman (uid=/gid= refuses par podman 5.7 ; docker-compose.server.yml)
    printf 'QUALIF_PRIVATE_DIR=%s\nQUALIF_TLS_DIR=%s\nQUALIF_NODE_A_ADDR=%s\nCHAIN_DIR=%s\nSECAGENT_TMPFS_OPTS=U\n' \
      "$PRIVATE_DIR/QUALIF" "$PRIVATE_DIR/QUALIF/pki" 192.168.1.213 "$PRIVATE_DIR/QUALIF/srv4/cyril/secagent/run"
  else
    printf 'STATE_HOST_DIR=%s\nSECRETS_DIR=%s\nTLS_CERT_DIR=%s\n' \
      "$PRIVATE_DIR/PROD/state/root" "$PRIVATE_DIR/PROD/secrets" "$PRIVATE_DIR/PROD/pki"
  fi
}

# Unite --user du noeud. Deterministe. Deposee sur le partage (systemd/, reference verifiee) puis COPIEE, apres
# verification, HORS partage dans ~/.config/systemd/user/ par `verify-node-files.sh --pin` : systemd ne lit donc jamais
# une unite modifiable depuis le partage (une unite liee serait relue telle quelle au boot, ExecStartPre compris).
node_unit() { # $1 env, $2 noeud (node_topology deja appele)
  cat <<EOF
# Genere par DEPLOYMENT/podman/stage-node-files.sh (#267) : conteneurs secagent $1 du noeud $2 (Podman rootless).
# Copiee hors partage par verify-node-files.sh --pin (jamais liee). A CHAQUE demarrage (boot, Restart=, relance), avant
# tout : 1) empreintes de bin/, release/ et systemd/ du partage comparees au manifeste epingle HORS partage
# (%h/$PIN_REL, ecrit par verify-node-files.sh --pin apres verification contre le depot) ; 2) garde check-private.sh
# (desormais verifiee) : partage, modes, pki/, et liste EXACTE des fichiers = celle du manifeste (rien en trop, ex. .env).
# Partage absent : 1) echoue (fail-closed), nouvel essai par Restart= (3 en 600 s).
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
ExecStartPre=/usr/bin/sha256sum --quiet --strict -c %h/$PIN_REL
ExecStartPre=$NODE_BASE/bin/check-private.sh $1 $2 %h/$PIN_REL
ExecStart=/usr/bin/podman-compose -p $PROJECT_NAME $COMPOSE_ARGS up -d $NODE_SERVICES
ExecStop=/usr/bin/podman-compose -p $PROJECT_NAME $COMPOSE_ARGS stop $NODE_SERVICES
Restart=on-failure
RestartSec=30
TimeoutStartSec=600

[Install]
WantedBy=default.target
EOF
}

# Manifeste ATTENDU "sha256  sous-dossier/nom" (bin/, release/ et systemd/), recalcule depuis le depot dans $1 (repertoire
# temporaire de l'appelant) : garde du depot, copies des sources, release.env et unite generes.
expected_tree() { # $1 repertoire de sortie, $2 env, $3 noeud
  local out="$1" f
  mkdir -p "$out/bin" "$out/release" "$out/systemd"
  cp "$REPO/DEPLOYMENT/podman/check-private.sh" "$out/bin/check-private.sh"; chmod 700 "$out/bin/check-private.sh"
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
  local sub; for sub in bin release systemd; do ( cd "$out/$sub" && sha256sum -- * > SHA256SUMS ); done
}

# Manifeste epingle (format sha256sum -c, chemins ABSOLUS sur le partage) : garde, release/ et unite, depuis l'attendu.
pin_manifest() { # $1 repertoire produit par expected_tree
  local f
  ( cd "$1" && find bin release systemd -type f -print | LC_ALL=C sort ) | while read -r f; do
    printf '%s  %s\n' "$(sha256sum < "$1/$f" | cut -d' ' -f1)" "$NODE_BASE/$f"
  done
}
