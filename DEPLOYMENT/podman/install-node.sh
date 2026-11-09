#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Preparation REDUITE d'un noeud Podman rootless (LOT-4 v3.0.6, #267) : etapes ROOT seulement, compte `cyril` existant.
# Execute depuis le poste, jamais copie sur le noeud :
#
#   ssh -i PRIVATE/<ENV>/poste-cyril/id_ed25519 -o UserKnownHostsFile=PRIVATE/<ENV>/poste-cyril/known_hosts \
#       -o StrictHostKeyChecking=yes cyril@<ip> sudo bash -s -- <qualif|prod> < DEPLOYMENT/podman/install-node.sh
#
# Fait, dans cet ordre (idempotent, s'arrete au premier refus) :
#   1. controles (lecture seule) : root, compte cyril (uid 1000), /etc/subuid et /etc/subgid de cyril, newuidmap,
#      podman >= 4.3 (keep-id:uid=), podman-compose >= 1.2 (userns_mode), pasta (passt) ou slirp4netns ;
#      Podman n'est JAMAIS installe ici (decision utilisateur : deja installe) ;
#   2. `apt-get install -y moosefs-client` si mfsmount est absent (SEUL paquet installe) ;
#   3. `loginctl enable-linger cyril` (unites --user actives sans session ouverte : montage, podman.socket) ;
#   4. `install -d -o cyril -m 700 /home/cyril/secagent/<env>` (point de montage) ;
#   5. ecrit (sans l'activer) l'unite --user `secagent-<env>-mfs.service` : montage UTILISATEUR de PRIVATE/<ENV>/
#      (mfsmount sans allow_other : /etc/fuse.conf n'est pas touche). Activation par cyril, SANS sudo (etape suivante
#      affichee a la fin) ; podman.socket --user et les unites de conteneurs aussi.
#
# INTERDITS CODES (act() refuse toute commande qui les vise, code 3) : docker, kubectl, k3s, rke2, containerd, crictl,
#   helm, rancher ; /opt/MFS ; daemon.json ; arret/redemarrage/suppression de services ou de conteneurs (systemctl
#   stop|restart|disable|mask, podman stop|rm|kill|rmi|system reset) ; useradd/usermod/userdel/groupadd, sudoers,
#   sshd_config ; mfsmaster/mfschunkserver/mfsmetalogger (serveurs MooseFS).
#
# Codes : 0 OK ; 2 refus d'une precondition (REFUS:) ; 3 commande interdite (INTERDIT:) ; 1 echec d'execution (ECHEC:).
# Variables (essais seulement) : NODE_USER (cyril), NODE_UID (1000), HOME_BASE (/home), SUBID_DIR (/etc),
#   MFS_MASTER (192.168.1.231), MFS_SUBDIR (/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/<ENV>).
set -euo pipefail

NODE_USER="${NODE_USER:-cyril}"
NODE_UID="${NODE_UID:-1000}"
HOME_BASE="${HOME_BASE:-/home}"
SUBID_DIR="${SUBID_DIR:-/etc}"
MFS_MASTER="${MFS_MASTER:-192.168.1.231}"
PODMAN_MIN=4.3
PODMAN_COMPOSE_MIN=1.2

refuse() { echo "REFUS: $*" >&2; exit 2; }
fail() { echo "ECHEC: $*" >&2; exit 1; }

# Liste de refus : evaluee sur la ligne de commande COMPLETE (mots separes par des espaces) avant toute execution.
forbidden() { # $* commande ; 0 si interdite (motif affiche sur stdout)
  local line=" $* " w
  for w in docker dockerd kubectl k3s rke2 containerd crictl ctr helm rancher useradd usermod userdel groupadd \
           groupmod visudo mfsmaster mfschunkserver mfsmetalogger; do
    case "$line" in *" $w "*|*"/$w "*) echo "$w"; return 0 ;; esac
  done
  case "$line" in
    */opt/MFS*) echo "/opt/MFS"; return 0 ;;
    *daemon.json*) echo "daemon.json"; return 0 ;;
    *sudoers*) echo "sudoers"; return 0 ;;
    *sshd_config*) echo "sshd_config"; return 0 ;;
  esac
  # sous-commande n'importe ou apres l'outil (options intercalees : `systemctl --user stop`, `podman rm -f`)
  local re_sys='[[:space:]/]systemctl[[:space:]](.*[[:space:]])?(stop|restart|try-restart|reload-or-restart|disable|mask|kill)[[:space:]]'
  local re_pod='[[:space:]/]podman[[:space:]](.*[[:space:]])?(stop|rm|kill|rmi|reset|prune|pod)[[:space:]]'
  if [[ $line =~ $re_sys ]]; then echo "systemctl ${BASH_REMATCH[2]}"; return 0; fi
  if [[ $line =~ $re_pod ]]; then echo "podman ${BASH_REMATCH[2]}"; return 0; fi
  return 1
}
act() { # execute "$@" apres controle de la liste de refus
  local why
  if why="$(forbidden "$@")"; then echo "INTERDIT: '$*' ($why) : refuse par install-node.sh" >&2; exit 3; fi
  "$@"
}

ver_ge() { # $1 >= $2 (versions numeriques pointees)
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}
first_version() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1; }

check_preconditions() {
  [ "$(id -u)" = 0 ] || refuse "a executer en root (ssh $NODE_USER@<ip> sudo bash -s -- <env> < install-node.sh)"
  local uid; uid="$(id -u "$NODE_USER" 2>/dev/null)" || refuse "compte $NODE_USER absent (aucun compte n'est cree par ce script)"
  [ "$uid" = "$NODE_UID" ] || refuse "compte $NODE_USER : uid $uid, attendu $NODE_UID (keep-id:uid=10001 -> fichiers uid $NODE_UID du partage)"
  local f; for f in subuid subgid; do
    grep -qE "^($NODE_USER|$NODE_UID):[0-9]+:[0-9]+$" "$SUBID_DIR/$f" 2>/dev/null \
      || refuse "$SUBID_DIR/$f : aucune plage pour $NODE_USER (requis par Podman rootless ; a ajouter par l'utilisateur)"
  done
  command -v newuidmap >/dev/null 2>&1 && command -v newgidmap >/dev/null 2>&1 || refuse "newuidmap/newgidmap absents (paquet uidmap : a installer par l'utilisateur avec Podman)"
  command -v podman >/dev/null 2>&1 || refuse "podman absent (installation par l'utilisateur, jamais par ce script)"
  local v; v="$(podman --version 2>/dev/null | first_version)" || true
  [ -n "$v" ] && ver_ge "$v" "$PODMAN_MIN" || refuse "podman ${v:-illisible} < $PODMAN_MIN (userns_mode keep-id:uid= requis)"
  command -v podman-compose >/dev/null 2>&1 || refuse "podman-compose absent (installation par l'utilisateur)"
  v="$(podman-compose version 2>/dev/null | grep -i 'podman-compose' | first_version)" || true
  [ -n "$v" ] && ver_ge "$v" "$PODMAN_COMPOSE_MIN" || refuse "podman-compose ${v:-illisible} < $PODMAN_COMPOSE_MIN (userns_mode transmis)"
  command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1 || refuse "ni pasta (passt) ni slirp4netns : reseau rootless indisponible"
  echo "preconditions OK (podman, podman-compose, reseau rootless, $NODE_USER uid $NODE_UID)"
}

main() {
  local env="${1:-}" ENV mnt unit_dir unit
  case "$env" in qualif|prod) ;; *) refuse "environnement '$env' : attendu qualif|prod" ;; esac
  ENV="$(printf '%s' "$env" | tr '[:lower:]' '[:upper:]')"
  local subdir="${MFS_SUBDIR:-/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/$ENV}"
  check_preconditions
  if command -v mfsmount >/dev/null 2>&1; then
    echo "moosefs-client deja present ($(command -v mfsmount))"
  else
    act env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends moosefs-client || fail "apt-get install moosefs-client"
  fi
  act loginctl enable-linger "$NODE_USER" || fail "loginctl enable-linger $NODE_USER"
  mnt="$HOME_BASE/$NODE_USER/secagent/$env"
  act install -d -o "$NODE_USER" -g "$NODE_USER" -m 700 "$HOME_BASE/$NODE_USER/secagent" "$mnt"
  unit_dir="$HOME_BASE/$NODE_USER/.config/systemd/user"
  act install -d -o "$NODE_USER" -g "$NODE_USER" -m 755 "$HOME_BASE/$NODE_USER/.config" "$HOME_BASE/$NODE_USER/.config/systemd" "$unit_dir"
  unit="$unit_dir/secagent-$env-mfs.service"
  # mfsmount -f (premier plan, suivi par systemd), sans allow_other : seuls les processus de cyril (dont les conteneurs
  # rootless) accedent au montage. Le point de montage doit etre vide : un montage deja present n'est pas touche.
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<EOF
# Genere par DEPLOYMENT/podman/install-node.sh (#267) : montage utilisateur de PRIVATE/$ENV (MooseFS), sans allow_other.
[Unit]
Description=secagent $env : montage MooseFS de PRIVATE/$ENV
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/mfsmount -f -H $MFS_MASTER -S $subdir $mnt
ExecStop=/usr/bin/fusermount3 -u $mnt
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
  act install -o "$NODE_USER" -g "$NODE_USER" -m 644 "$tmp" "$unit"
  rm -f "$tmp"
  echo "install-node OK ($env) : unite $unit ecrite, NON activee."
  echo "Etape suivante, en $NODE_USER SANS sudo : systemctl --user daemon-reload && systemctl --user enable --now secagent-$env-mfs.service podman.socket"
}

[ "${INSTALL_NODE_SOURCED:-0}" = 1 ] || main "$@"
