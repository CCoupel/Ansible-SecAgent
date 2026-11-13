#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Preparation REDUITE d'un noeud Podman rootless (LOT-4 v3.0.6, #267) : compte `cyril` existant, AUCUN paquet installe.
# Execute depuis le poste, jamais copie sur le noeud, APRES `prepare-node-files.sh <env> <srvX>` (poste) :
#
#   ssh -i PRIVATE/<ENV>/poste-cyril/id_ed25519 -o UserKnownHostsFile=PRIVATE/<ENV>/poste-cyril/known_hosts \
#       -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes cyril@<ip> sudo bash -s -- <qualif|prod> <srvX> < DEPLOYMENT/podman/install-node.sh
#
# Fichiers de deploiement du noeud CENTRALISES sur le partage (decision utilisateur) : PRIVATE/<ENV>/<srvX>/cyril/secagent/
# (bin/check-private.sh, release/, systemd/), crees depuis le poste. Sur le noeud ne restent que le linger et
# ~/.config/systemd/user, ou `verify-node-files.sh --pin` (poste, T44/T45) COPIE l'unite --user verifiee (jamais liee
# vers le partage) avec le manifeste epingle ~/.config/secagent/ : a chaque demarrage, ExecStartPre verifie les empreintes
# du partage puis la garde check-private.sh (partage inaccessible ou modifie = aucun conteneur, fail-closed).
#
# Noeuds COLOCALISES (decision utilisateur T42) : srv1-srv4 portent aussi RKE2 et des chunkservers MooseFS ; rien n'est
# touche cote k8s ni MooseFS. Acces au partage : BIND du montage autofs root EXISTANT
# /share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/<ENV> (aucun mfsmount, aucun moosefs-client, aucun apt).
# CLOISONNEMENT QUALIF/PROD (risque ACCEPTE par l'utilisateur, a documenter en T53) : l'autofs monte la racine MooseFS
# entiere ; un noeud QUALIF voit donc aussi PRIVATE/PROD (et inversement), protege seulement par les modes 0700 et
# l'uid 1000 commun. Rien dans ce script ne l'empeche ; la garde verifie seulement l'ENV demande.
#
# Fait, dans cet ordre (idempotent, s'arrete au premier refus) :
#   1. controles (lecture seule) : root, compte cyril (uid 1000), plage /etc/subuid et /etc/subgid >= 65536, newuidmap,
#      podman >= 4.3 (keep-id:uid=), podman-compose >= 1.2 (userns_mode), pasta ou slirp4netns, runuser ; espace disque du
#      home : REFUS sous MIN_FREE_GB (5) Gio libres, ATTENTION au-dela de WARN_PCT (70) % d'occupation ;
#   2. `loginctl enable-linger cyril` (unites --user actives sans session : podman.socket, conteneurs) ;
#   3. controleur cgroup v2 `memory` delegue a cyril (sinon les limites memoire des conteneurs rootless sont IGNOREES) :
#      REFUS sinon — les limites memoire de TOUS les conteneurs (Compose) sont obligatoires sur ces noeuds partages ;
#   4. EN cyril (runuser, jamais d'ecriture root dans son home ; repertoires existants jamais modifies, liens refuses) :
#      ~/.config/systemd/user SEULEMENT (aucun ~/secagent sur le noeud) ;
#   5. EXECUTE en cyril la garde du partage PRIVATE/<ENV>/<srvX>/cyril/secagent/bin/check-private.sh <env> <srvX> :
#      REFUS si PRIVATE/<ENV> ou les fichiers du noeud sont inaccessibles (autofs non monte, chemin absent, non FUSE,
#      proprietaire ou modes inattendus, sous-dossiers manquants) ou si la garde n'est pas 0700 / uid 1000.
#   Le noeud courant (`uname -n` sans domaine) doit etre <srvX> : refus sinon (fichiers d'un autre noeud).
#
# INTERDITS CODES (act() refuse toute commande qui les vise, code 3) : paquets (apt, apt-get, dpkg, snap) ; docker,
#   nerdctl, buildah, kubectl, k3s, rke2, containerd, crictl, ctr, helm, rancher ; MooseFS (mfsmount, mfsmaster,
#   mfschunkserver, mfsmetalogger, /opt/MFS) ; daemon.json ; arret/redemarrage de services, de conteneurs ou du noeud
#   (systemctl stop|restart|disable|mask|kill, service, reboot, shutdown, poweroff, halt, telinit, kill/pkill/killall,
#   podman stop|rm|kill|rmi|reset|prune|pod) ; pare-feu (iptables, ip6tables, nft, ufw, firewall-cmd) ; comptes
#   (useradd/usermod/userdel/groupadd/groupmod, visudo, sudoers, sshd_config) ; interpreteur avec -c (sh/bash/dash/zsh/ksh)
#   et eval. act() est un GARDE-FOU TEXTUEL, PAS UN SANDBOX : la garantie repose sur le texte FIXE de ce script (aucune
#   entree externe n'atteint act() : seuls <env> <srvX> sont lus, bornes a qualif srv3|srv4 / prod srv1|srv2) et sur l'analyse statique de son
#   selftest.
#
# Codes : 0 OK ; 2 refus d'une precondition (REFUS:) ; 3 commande interdite (INTERDIT:) ; 1 echec d'execution (ECHEC:).
# Variables (essais seulement, validees : refus si forme invalide) : NODE_USER (cyril), NODE_UID (1000), HOME_BASE (/home),
#   SUBID_DIR (/etc), CGROUP_ROOT (/sys/fs/cgroup), PRIVATE_ROOT (/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE),
#   MIN_FREE_GB (5), WARN_PCT (70), NODE_NAME (`uname -n` sans domaine). Via `sudo` (env_reset), aucune n'est transmise depuis le poste.
set -euo pipefail

NODE_USER="${NODE_USER:-cyril}"
NODE_UID="${NODE_UID:-1000}"
HOME_BASE="${HOME_BASE:-/home}"
SUBID_DIR="${SUBID_DIR:-/etc}"
CGROUP_ROOT="${CGROUP_ROOT:-/sys/fs/cgroup}"
PRIVATE_ROOT="${PRIVATE_ROOT:-/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE}"
MIN_FREE_GB="${MIN_FREE_GB:-5}"
WARN_PCT="${WARN_PCT:-70}"
PODMAN_MIN=4.3
PODMAN_COMPOSE_MIN=1.2
SUBID_MIN=65536

refuse() { echo "REFUS: $*" >&2; exit 2; }
fail() { echo "ECHEC: $*" >&2; exit 1; }

# Liste de refus : evaluee sur la ligne de commande COMPLETE (mots separes par des espaces) avant toute execution.
forbidden() { # $* commande ; 0 si interdite (motif affiche sur stdout)
  local line=" $* " w
  for w in apt apt-get dpkg snap docker dockerd nerdctl buildah kubectl k3s rke2 containerd crictl ctr helm rancher \
           useradd usermod userdel groupadd groupmod visudo mfsmount mfsmaster mfschunkserver mfsmetalogger service \
           reboot shutdown poweroff halt telinit kill pkill killall iptables ip6tables nft ufw firewall-cmd eval; do
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
  local re_sh='[[:space:]/](sh|bash|dash|zsh|ksh)[[:space:]](.*[[:space:]])?-[A-Za-z]*c[A-Za-z]*[[:space:]]'
  if [[ $line =~ $re_sys ]]; then echo "systemctl ${BASH_REMATCH[2]}"; return 0; fi
  if [[ $line =~ $re_pod ]]; then echo "podman ${BASH_REMATCH[2]}"; return 0; fi
  if [[ $line =~ $re_sh ]]; then echo "${BASH_REMATCH[1]} -c"; return 0; fi
  return 1
}
act() { # execute "$@" apres controle de la liste de refus
  local why
  if why="$(forbidden "$@")"; then echo "INTERDIT: '$*' ($why) : refuse par install-node.sh" >&2; exit 3; fi
  "$@"
}
as_user() { act runuser -u "$NODE_USER" -- "$@"; }   # ecritures dans le home de cyril : en cyril, jamais en root

ver_ge() { # $1 >= $2 (versions numeriques pointees)
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}
first_version() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1; }

# Forme des variables d'essai : elles sont interpolees dans la garde ecrite sur le noeud et des chemins.
safe_path() { [[ $1 =~ ^/[A-Za-z0-9_./-]*$ ]] && [[ ! /$1/ =~ /\.\./ ]]; }
validate_vars() {
  [[ $NODE_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || refuse "NODE_USER='$NODE_USER' invalide"
  [[ $NODE_UID =~ ^[0-9]{1,10}$ ]] || refuse "NODE_UID='$NODE_UID' invalide"
  local v; for v in HOME_BASE SUBID_DIR CGROUP_ROOT PRIVATE_ROOT; do
    safe_path "${!v}" || refuse "$v='${!v}' invalide (chemin absolu [A-Za-z0-9_./-], sans ..)"
  done
  [[ $MIN_FREE_GB =~ ^[0-9]{1,6}$ ]] || refuse "MIN_FREE_GB='$MIN_FREE_GB' invalide"
  [[ $WARN_PCT =~ ^[0-9]{1,3}$ ]] || refuse "WARN_PCT='$WARN_PCT' invalide"
  [ -z "${NODE_NAME:-}" ] || [[ $NODE_NAME =~ ^[a-z0-9][a-z0-9.-]{0,62}$ ]] || refuse "NODE_NAME='$NODE_NAME' invalide"
}

check_preconditions() {
  [ "$(id -u)" = 0 ] || refuse "a executer en root (ssh $NODE_USER@<ip> sudo bash -s -- <env> < install-node.sh)"
  local uid; uid="$(id -u "$NODE_USER" 2>/dev/null)" || refuse "compte $NODE_USER absent (aucun compte n'est cree par ce script)"
  [ "$uid" = "$NODE_UID" ] || refuse "compte $NODE_USER : uid $uid, attendu $NODE_UID (keep-id:uid=10001 -> fichiers uid $NODE_UID du partage)"
  local f size; for f in subuid subgid; do
    size="$(awk -F: -v u="$NODE_USER" -v i="$NODE_UID" '($1==u || $1==i) && NF==3 && $3 ~ /^[0-9]+$/ {print $3; exit}' "$SUBID_DIR/$f" 2>/dev/null)" || true
    [ -n "$size" ] || refuse "$SUBID_DIR/$f : aucune plage pour $NODE_USER (requis par Podman rootless ; a ajouter par l'utilisateur)"
    [ "$size" -ge "$SUBID_MIN" ] || refuse "$SUBID_DIR/$f : plage de $NODE_USER de $size uid, minimum $SUBID_MIN (keep-id:uid=10001)"
  done
  command -v newuidmap >/dev/null 2>&1 && command -v newgidmap >/dev/null 2>&1 || refuse "newuidmap/newgidmap absents (paquet uidmap : a installer par l'utilisateur avec Podman)"
  command -v podman >/dev/null 2>&1 || refuse "podman absent (installation par l'utilisateur, jamais par ce script)"
  local v; v="$(podman --version 2>/dev/null | first_version)" || true
  [ -n "$v" ] && ver_ge "$v" "$PODMAN_MIN" || refuse "podman ${v:-illisible} < $PODMAN_MIN (userns_mode keep-id:uid= requis)"
  command -v podman-compose >/dev/null 2>&1 || refuse "podman-compose absent (installation par l'utilisateur)"
  v="$(podman-compose version 2>/dev/null | grep -i 'podman-compose' | first_version)" || true
  [ -n "$v" ] && ver_ge "$v" "$PODMAN_COMPOSE_MIN" || refuse "podman-compose ${v:-illisible} < $PODMAN_COMPOSE_MIN (userns_mode transmis)"
  command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1 || refuse "ni pasta (passt) ni slirp4netns : reseau rootless indisponible"
  command -v runuser >/dev/null 2>&1 || refuse "runuser absent (util-linux) : ecritures en $NODE_USER impossibles"
  echo "preconditions OK (podman, podman-compose, reseau rootless, $NODE_USER uid $NODE_UID)"
}

# Espace disque du home (images et couches Podman rootless : ~/.local/share/containers) ; noeud partage avec RKE2.
check_disk() { # $1 home
  local out avail pct
  out="$(df -k --output=avail,pcent "$1" 2>/dev/null | tail -n 1)" || refuse "df $1 illisible"
  read -r avail pct <<< "$out"; pct="${pct%\%}"
  [[ $avail =~ ^[0-9]+$ && $pct =~ ^[0-9]+$ ]] || refuse "df $1 : sortie inattendue ($out)"
  [ $(( avail / 1048576 )) -ge "$MIN_FREE_GB" ] || refuse "espace disque de $1 : $(( avail / 1048576 )) Gio libres, minimum $MIN_FREE_GB Gio (noeud partage avec RKE2 : liberer de l'espace)"
  if [ "$pct" -ge "$WARN_PCT" ]; then
    echo "ATTENTION: $1 occupe a $pct % ($(( avail / 1048576 )) Gio libres) : noeud partage avec RKE2 et des chunkservers, surveiller les images Podman"
  else
    echo "disque $1 : $pct % occupe, $(( avail / 1048576 )) Gio libres"
  fi
}

# Limites memoire des conteneurs rootless : effectives seulement si le controleur `memory` est delegue a l'utilisateur.
check_cgroup_memory() {
  local f="$CGROUP_ROOT/user.slice/user-$NODE_UID.slice/user@$NODE_UID.service/cgroup.controllers"
  [ -r "$f" ] || refuse "$f absent : gestionnaire systemd --user de $NODE_USER non demarre (linger ?) ou cgroup v1"
  grep -qw memory "$f" || refuse "controleur cgroup 'memory' non delegue a $NODE_USER ($f : $(cat "$f")) : les limites memoire des conteneurs seraient ignorees"
  echo "cgroup v2 : controleurs delegues a $NODE_USER : $(cat "$f")"
}

# Repertoire de cyril cree EN cyril s'il manque ; un existant n'est jamais modifie ; un lien est refuse.
user_dir() { # $1 chemin
  [ ! -L "$1" ] || refuse "$1 est un lien symbolique : refus"
  if [ -e "$1" ]; then [ -d "$1" ] || refuse "$1 existe et n'est pas un repertoire"; return 0; fi
  as_user install -d -m 700 "$1"
}

main() {
  local env="${1:-}" node="${2:-}" ENV home here guard
  case "$env:$node" in
    qualif:srv3|qualif:srv4) ENV=QUALIF ;;
    prod:srv1|prod:srv2) ENV=PROD ;;
    *) refuse "couple '$env $node' : attendu qualif srv3|srv4 ou prod srv1|srv2" ;;
  esac
  validate_vars
  here="${NODE_NAME:-$(uname -n)}"; here="${here%%.*}"
  [ "$here" = "$node" ] || refuse "noeud courant '$here' different de '$node' : refus (fichiers d'un autre noeud)"
  check_preconditions
  home="$HOME_BASE/$NODE_USER"
  [ -d "$home" ] && [ ! -L "$home" ] || refuse "home $home absent ou lien symbolique"
  check_disk "$home"
  act loginctl enable-linger "$NODE_USER" || fail "loginctl enable-linger $NODE_USER"
  check_cgroup_memory
  user_dir "$home/.config"; user_dir "$home/.config/systemd"; user_dir "$home/.config/systemd/user"
  guard="$PRIVATE_ROOT/$ENV/$node/cyril/secagent/bin/check-private.sh"
  timeout 30 test -f "$guard" || refuse "$guard absent ou partage inaccessible : lancer d'abord prepare-node-files.sh $env $node sur le poste"
  [ ! -L "$guard" ] || refuse "$guard est un lien symbolique : refus"
  [ "$(stat -c '%u %a' "$guard")" = "$NODE_UID 700" ] || refuse "$guard : $(stat -c '%u %a' "$guard"), attendu uid $NODE_UID mode 700"
  as_user env SECAGENT_PRIVATE_ROOT="$PRIVATE_ROOT" SECAGENT_NODE_UID="$NODE_UID" SECAGENT_NODE_NAME="$here" "$guard" "$env" "$node" \
    || refuse "garde PRIVATE en echec pour $env $node (voir message ci-dessus) : aucun conteneur ne doit demarrer"
  echo "install-node OK ($env $node) : linger, ~/.config/systemd/user, garde du partage conforme. Rien d'autre sur le noeud."
  echo "Etape suivante, en $NODE_USER SANS sudo : systemctl --user enable --now podman.socket ; unites (T44/T45) : copiees depuis le poste par verify-node-files.sh --pin $env $node (jamais systemctl --user link), puis daemon-reload"
}

[ "${INSTALL_NODE_SOURCED:-0}" = 1 ] || main "$@"
