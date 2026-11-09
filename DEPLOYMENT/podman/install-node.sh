#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Preparation REDUITE d'un noeud Podman rootless (LOT-4 v3.0.6, #267) : etapes ROOT seulement, compte `cyril` existant.
# Execute depuis le poste, jamais copie sur le noeud :
#
#   ssh -i PRIVATE/<ENV>/poste-cyril/id_ed25519 -o UserKnownHostsFile=PRIVATE/<ENV>/poste-cyril/known_hosts \
#       -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes cyril@<ip> sudo bash -s -- <qualif|prod> < DEPLOYMENT/podman/install-node.sh
#
# Fait, dans cet ordre (idempotent, s'arrete au premier refus) :
#   1. controles (lecture seule) : root, compte cyril (uid 1000), plage /etc/subuid et /etc/subgid de cyril (>= 65536),
#      newuidmap, podman >= 4.3 (keep-id:uid=), podman-compose >= 1.2 (userns_mode), pasta (passt) ou slirp4netns ;
#      Podman n'est JAMAIS installe ici (decision utilisateur : deja installe) ;
#   2. si mfsmount est absent : SIMULATION `apt-get -s` (refus si elle retire un paquet, en met un a jour, ou installe
#      autre chose que moosefs-* / fuse3 / libfuse3-*), puis `apt-get install --no-upgrade moosefs-client` avec
#      NEEDRESTART_MODE=l et NEEDRESTART_SUSPEND=1 : le hook needrestart ne redemarre AUCUN service (docker, containerd,
#      rke2... portes par ces noeuds) ; c'est le SEUL paquet installe ;
#   3. `loginctl enable-linger cyril` (unites --user actives sans session ouverte : montage, podman.socket) ;
#   4. EN cyril (runuser, jamais d'ecriture root dans son home) : ~/secagent/<env> 0700 (point de montage, refuse s'il
#      est un lien ou non vide hors montage ; laisse tel quel s'il est deja monte), ~/.config/systemd/user cree s'il manque
#      (modes des repertoires existants jamais modifies) ;
#   5. ecrit (sans l'activer) l'unite --user `secagent-<env>-mfs.service` : montage UTILISATEUR de PRIVATE/<ENV>/
#      (`mfsmount -n`, sans allow_other : /etc/fuse.conf n'est pas touche ; ExecStartPost echoue si le point de montage
#      n'est pas monte en 30 s). Activation par cyril SANS sudo (etape affichee a la fin), comme podman.socket --user.
#      Les unites de conteneurs (T44/T45) devront porter `Requires=`/`After=` sur cette unite et `RequiresMountsFor=`.
#
# INTERDITS CODES (act() refuse toute commande qui les vise, code 3) : docker, nerdctl, buildah, kubectl, k3s, rke2,
#   containerd, crictl, ctr, helm, rancher ; /opt/MFS ; daemon.json ; arret/redemarrage de services, de conteneurs ou du
#   noeud (systemctl stop|restart|disable|mask|kill, service, reboot, shutdown, poweroff, halt, telinit, kill/pkill/killall,
#   podman stop|rm|kill|rmi|reset|prune|pod) ; pare-feu (iptables, ip6tables, nft, ufw, firewall-cmd) ;
#   useradd/usermod/userdel/groupadd/groupmod, visudo, sudoers, sshd_config ; serveurs MooseFS (mfsmaster, mfschunkserver,
#   mfsmetalogger) ; interpreteur avec -c (sh/bash/dash/zsh/ksh -c) et eval.
#   act() est un GARDE-FOU TEXTUEL, PAS UN SANDBOX : il ne voit que la ligne de commande (pas les hooks d'un paquet, d'ou
#   la simulation et NEEDRESTART_* de l'etape 2). La garantie repose sur le texte FIXE de ce script (aucune entree externe
#   n'atteint act() : seul l'argument <env> est lu, borne a qualif|prod) et sur l'analyse statique de son selftest.
#
# Codes : 0 OK ; 2 refus d'une precondition (REFUS:) ; 3 commande interdite (INTERDIT:) ; 1 echec d'execution (ECHEC:).
# Variables (essais seulement, validees : refus si forme invalide) : NODE_USER (cyril), NODE_UID (1000), HOME_BASE
#   (/home), SUBID_DIR (/etc), MFS_MASTER (192.168.1.231), MFS_SUBDIR (/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/<ENV>).
#   Via `sudo` (env_reset), aucune n'est transmise depuis le poste : les valeurs par defaut s'appliquent.
set -euo pipefail

NODE_USER="${NODE_USER:-cyril}"
NODE_UID="${NODE_UID:-1000}"
HOME_BASE="${HOME_BASE:-/home}"
SUBID_DIR="${SUBID_DIR:-/etc}"
MFS_MASTER="${MFS_MASTER:-192.168.1.231}"
PODMAN_MIN=4.3
PODMAN_COMPOSE_MIN=1.2
SUBID_MIN=65536
# Paquets que l'installation de moosefs-client peut AJOUTER (simulation apt) ; toute autre installation, toute mise a jour
# d'un paquet present et tout retrait sont refuses.
TMP_UNIT=""
APT_ALLOWED='^(moosefs-[a-z0-9.+-]+|fuse3|libfuse3-[0-9]+)$'

refuse() { echo "REFUS: $*" >&2; exit 2; }
fail() { echo "ECHEC: $*" >&2; exit 1; }

# Liste de refus : evaluee sur la ligne de commande COMPLETE (mots separes par des espaces) avant toute execution.
forbidden() { # $* commande ; 0 si interdite (motif affiche sur stdout)
  local line=" $* " w
  for w in docker dockerd nerdctl buildah kubectl k3s rke2 containerd crictl ctr helm rancher useradd usermod userdel \
           groupadd groupmod visudo mfsmaster mfschunkserver mfsmetalogger service reboot shutdown poweroff halt telinit \
           kill pkill killall iptables ip6tables nft ufw firewall-cmd eval; do
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

# Forme des variables d'essai : elles sont interpolees dans l'unite systemd et des expressions grep.
safe_path() { [[ $1 =~ ^/[A-Za-z0-9_./-]*$ ]] && [[ ! /$1/ =~ /\.\./ ]]; }
validate_vars() {
  [[ $NODE_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || refuse "NODE_USER='$NODE_USER' invalide"
  [[ $NODE_UID =~ ^[0-9]{1,10}$ ]] || refuse "NODE_UID='$NODE_UID' invalide"
  safe_path "$HOME_BASE" || refuse "HOME_BASE='$HOME_BASE' invalide (chemin absolu [A-Za-z0-9_./-], sans ..)"
  safe_path "$SUBID_DIR" || refuse "SUBID_DIR='$SUBID_DIR' invalide"
  [[ $MFS_MASTER =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || $MFS_MASTER =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] \
    || refuse "MFS_MASTER='$MFS_MASTER' invalide (IPv4 ou nom d'hote)"
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
  command -v mountpoint >/dev/null 2>&1 || refuse "mountpoint absent (util-linux)"
  echo "preconditions OK (podman, podman-compose, reseau rootless, $NODE_USER uid $NODE_UID)"
}

# Etape 2 : moosefs-client, sans redemarrage de service ni mise a jour d'un paquet present.
install_moosefs_client() {
  local sim line pkg
  sim="$(act env LC_ALL=C apt-get -s install -y --no-install-recommends --no-upgrade moosefs-client 2>&1)" \
    || refuse "simulation apt-get de moosefs-client en echec : $(printf '%s' "$sim" | tail -n 3 | tr '\n' ' ')"
  while IFS= read -r line; do
    case "$line" in
      Remv\ *) refuse "simulation apt : retrait prevu ($line) : installation refusee" ;;
      Inst\ *)
        pkg="${line#Inst }"; pkg="${pkg%% *}"
        case "$line" in "Inst $pkg ["*) refuse "simulation apt : mise a jour d'un paquet present ($line) : refusee" ;; esac
        [[ $pkg =~ $APT_ALLOWED ]] || refuse "simulation apt : installation hors liste ($pkg) : refusee (seuls moosefs-*, fuse3, libfuse3-*)" ;;
    esac
  done <<< "$sim"
  act env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
    apt-get install -y --no-install-recommends --no-upgrade moosefs-client || fail "apt-get install moosefs-client"
}

# Repertoire de cyril cree EN cyril s'il manque ; un existant n'est jamais modifie ; un lien est refuse.
user_dir() { # $1 chemin
  [ ! -L "$1" ] || refuse "$1 est un lien symbolique : refus"
  if [ -e "$1" ]; then [ -d "$1" ] || refuse "$1 existe et n'est pas un repertoire"; return 0; fi
  as_user install -d -m 700 "$1"
}

main() {
  local env="${1:-}" ENV home mnt unit_dir unit
  case "$env" in qualif|prod) ;; *) refuse "environnement '$env' : attendu qualif|prod" ;; esac
  ENV="$(printf '%s' "$env" | tr '[:lower:]' '[:upper:]')"
  local subdir="${MFS_SUBDIR:-/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/$ENV}"
  validate_vars
  safe_path "$subdir" || refuse "MFS_SUBDIR='$subdir' invalide (chemin absolu [A-Za-z0-9_./-], sans ..)"
  check_preconditions
  home="$HOME_BASE/$NODE_USER"
  [ -d "$home" ] && [ ! -L "$home" ] || refuse "home $home absent ou lien symbolique"
  mnt="$home/secagent/$env"
  if command -v mfsmount >/dev/null 2>&1; then
    echo "moosefs-client deja present ($(command -v mfsmount))"
  else
    install_moosefs_client
  fi
  act loginctl enable-linger "$NODE_USER" || fail "loginctl enable-linger $NODE_USER"
  user_dir "$home/secagent"
  if mountpoint -q "$mnt" 2>/dev/null; then
    echo "$mnt deja monte : non touche"
  else
    [ ! -L "$mnt" ] || refuse "$mnt est un lien symbolique : refus"
    if [ -e "$mnt" ]; then
      [ -d "$mnt" ] || refuse "$mnt existe et n'est pas un repertoire"
      [ -z "$(ls -A "$mnt")" ] || refuse "$mnt non vide hors montage (etat local ? le serveur ecrirait hors du partage) : a examiner par l'utilisateur"
      [ "$(stat -c %u "$mnt")" = "$NODE_UID" ] || refuse "$mnt n'appartient pas a $NODE_USER"
    fi
    as_user install -d -m 700 "$mnt"
  fi
  user_dir "$home/.config"; user_dir "$home/.config/systemd"; user_dir "$home/.config/systemd/user"
  unit_dir="$home/.config/systemd/user"
  unit="$unit_dir/secagent-$env-mfs.service"
  [ ! -L "$unit" ] || refuse "$unit est un lien symbolique : refus"
  # mfsmount -f (premier plan, suivi par systemd) -n (PAS les options standard `allow_other,fsname=MFS` : sans -n,
  # fusermount3 refuse le montage utilisateur faute de user_allow_other, constate en T42) : seuls les processus de cyril
  # (dont les conteneurs rootless) accedent au montage. -S est relatif a la racine MooseFS (= /share/MFS/ROOT des
  # clients autofs, carte /etc/auto.master.d/auto.MFS), donc sans le prefixe /ROOT. mfsmount refuse un point de montage
  # non vide ; ExecStartPost fait echouer l'unite si le montage n'est pas effectif en 30 s (jamais d'etat local muet).
  TMP_UNIT="$(mktemp)"; trap 'rm -f "$TMP_UNIT"' EXIT   # retire aussi sur refus/interdit (exit 2/3)
  cat > "$TMP_UNIT" <<EOF
# Genere par DEPLOYMENT/podman/install-node.sh (#267) : montage utilisateur de PRIVATE/$ENV (MooseFS), sans allow_other.
[Unit]
Description=secagent $env : montage MooseFS de PRIVATE/$ENV
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/mfsmount -f -n -H $MFS_MASTER -S $subdir $mnt
ExecStartPost=/bin/sh -c 'for i in \$\$(seq 1 30); do /usr/bin/mountpoint -q $mnt && exit 0; sleep 1; done; echo "$mnt non monte" >&2; exit 1'
ExecStop=/usr/bin/fusermount3 -u $mnt
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
  chmod 644 "$TMP_UNIT"   # lu par cyril (runuser) ; aucun secret
  as_user install -m 644 "$TMP_UNIT" "$unit"
  rm -f "$TMP_UNIT"
  echo "install-node OK ($env) : unite $unit ecrite, NON activee."
  echo "Etape suivante, en $NODE_USER SANS sudo : systemctl --user daemon-reload && systemctl --user enable --now secagent-$env-mfs.service podman.socket"
}

[ "${INSTALL_NODE_SOURCED:-0}" = 1 ] || main "$@"
