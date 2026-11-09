#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de DEPLOYMENT/podman/install-node.sh (#267) avec de faux `id`, `podman`, `podman-compose`, `loginctl`,
# `apt-get`, `runuser`, `mountpoint`... : sans root, sans noeud, sans reseau. Verifie les refus de preconditions et de
# forme des variables (code 2), la simulation apt et l'environnement needrestart de l'installation, la liste de refus de
# act() (code 3), le chemin nominal (montage utilisateur `-n`, ExecStartPost, unite ecrite non activee, repertoires
# existants non modifies, point de montage monte non touche) et l'absence de toute commande interdite dans le texte.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../../DEPLOYMENT/podman/install-node.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
ME="$(id -un)"; MYUID="$(id -u)"; REAL_ID="$(command -v id)"
SUB=/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE

mkstubs() { # $1 version podman, $2 version podman-compose, $3 reseau (pasta|none), $4 mfsmount (absent|present)
  rm -rf "$T/bin"; mkdir -p "$T/bin"
  cat > "$T/bin/id" <<EOF
#!/bin/sh
# root simule pour \`id -u\` sans argument ; sinon le vrai id
if [ "\$#" = 1 ] && [ "\$1" = -u ]; then echo "\${FAKE_EUID:-0}"; exit 0; fi
exec $REAL_ID "\$@"
EOF
  printf '#!/bin/sh\necho "podman version %s"\n' "$1" > "$T/bin/podman"
  printf '#!/bin/sh\necho "podman-compose version %s"\necho "podman version %s"\n' "$2" "$1" > "$T/bin/podman-compose"
  [ "$3" = pasta ] && printf '#!/bin/sh\nexit 0\n' > "$T/bin/pasta"
  [ "$4" = present ] && printf '#!/bin/sh\nexit 0\n' > "$T/bin/mfsmount"
  local c; for c in newuidmap newgidmap loginctl; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n' "$c" "$T" > "$T/bin/$c"
  done
  # faux apt-get : trace l'environnement needrestart et les arguments ; -s affiche le fichier $FAKE_APT_SIM
  cat > "$T/bin/apt-get" <<EOF
#!/bin/sh
echo "apt-get NEEDRESTART_MODE=\${NEEDRESTART_MODE:-} NEEDRESTART_SUSPEND=\${NEEDRESTART_SUSPEND:-} DEBIAN_FRONTEND=\${DEBIAN_FRONTEND:-} \$*" >> "$T/calls.log"
case " \$* " in *" -s "*) cat "\${FAKE_APT_SIM:-/dev/null}" ;; esac
EOF
  # faux runuser : trace puis execute la commande apres `--` (en utilisateur courant)
  cat > "$T/bin/runuser" <<EOF
#!/bin/sh
echo "runuser \$*" >> "$T/calls.log"
while [ "\$#" -gt 0 ] && [ "\$1" != -- ]; do shift; done; shift
exec "\$@"
EOF
  # faux mountpoint : monte = chemin egal a $FAKE_MOUNTED
  printf '#!/bin/sh\n[ "$1" = -q ] && shift\n[ -n "${FAKE_MOUNTED:-}" ] && [ "$1" = "$FAKE_MOUNTED" ]\n' > "$T/bin/mountpoint"
  chmod +x "$T/bin/"*
}
run() { # $@ arguments ; variables d'essai : home, subid et TMPDIR dans $T
  local extra=()
  [ -z "${XMASTER:-}" ] || extra+=("MFS_MASTER=$XMASTER")
  [ -z "${XSUBDIR:-}" ] || extra+=("MFS_SUBDIR=$XSUBDIR")
  env -i PATH="$T/bin:/usr/bin:/bin" NODE_USER="${XUSER:-$ME}" NODE_UID="${XUID:-$MYUID}" HOME_BASE="${XHOME:-$T/home}" \
    SUBID_DIR="$T/etc" TMPDIR="$T/tmp" FAKE_EUID="${FAKE_EUID:-0}" FAKE_MOUNTED="${FAKE_MOUNTED:-}" \
    FAKE_APT_SIM="${FAKE_APT_SIM:-}" "${extra[@]}" bash "$S" "$@"
}
expect_rc() { # $1 rc attendu, $2 nom, $3 motif attendu dans la sortie (optionnel), $4... arguments
  local want="$1" name="$2" pat="$3" out rc; shift 3
  out="$(run "$@" 2>&1)"; rc=$?
  [ "$rc" = "$want" ] && ok "$name (rc=$rc)" || ko "$name (rc=$rc, attendu $want) : $out"
  [ -z "$pat" ] || { printf '%s' "$out" | grep -qF -- "$pat" && ok "$name : message '$pat'" || ko "$name : message sans '$pat' : $out"; }
}
reset_env() {
  rm -rf "$T/home" "$T/etc" "$T/calls.log" "$T/tmp"; mkdir -p "$T/home/$ME" "$T/etc" "$T/tmp"
  printf '%s:100000:65536\n' "$ME" > "$T/etc/subuid"; printf '%s:100000:65536\n' "$ME" > "$T/etc/subgid"
}
H="$T/home/$ME"

# --- chemin nominal -------------------------------------------------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta absent
printf 'Inst moosefs-common (4.59.2-1 MooseFS:26.04 [amd64])\nInst libfuse3-4 (3.18.2-1 Ubuntu:26.04 [amd64])\nInst fuse3 (3.18.2-1 Ubuntu:26.04 [amd64])\nInst moosefs-client (4.59.2-1 MooseFS:26.04 [amd64])\nConf moosefs-client (4.59.2-1 MooseFS:26.04 [amd64])\n' > "$T/sim-ok"
FAKE_APT_SIM="$T/sim-ok" expect_rc 0 "nominal qualif" "NON activee" qualif
U="$H/.config/systemd/user/secagent-qualif-mfs.service"
[ -f "$U" ] && ok "unite --user ecrite" || ko "unite absente ($U)"
grep -q "^ExecStart=/usr/bin/mfsmount -f -n -H 192.168.1.231 -S $SUB/QUALIF $H/secagent/qualif$" "$U" \
  && ok "ExecStart : -n, master, sous-dossier PRIVATE/QUALIF (sans /ROOT), point de montage" || ko "ExecStart inattendu : $(grep ExecStart= "$U")"
grep -qE '^ExecStart=.*(allow_other|-o)' "$U" && ko "allow_other (ou -o) dans ExecStart" || ok "pas d'allow_other dans ExecStart"
grep -qF "ExecStartPost=/bin/sh -c 'for i in \$\$(seq 1 30); do /usr/bin/mountpoint -q $H/secagent/qualif && exit 0" "$U" \
  && ok "ExecStartPost : echec si non monte (\$\$ echappe pour systemd)" || ko "ExecStartPost absent ou mal echappe : $(grep ExecStartPost "$U")"
[ "$(stat -c %a "$H/secagent/qualif")" = 700 ] && ok "point de montage 0700" || ko "point de montage $(stat -c %a "$H/secagent/qualif")"
grep -q "^loginctl enable-linger $ME$" "$T/calls.log" && ok "linger active" || ko "linger non appele"
grep -q "^runuser -u $ME -- install -m 644 .* $U$" "$T/calls.log" && ok "unite ecrite EN $ME (runuser)" || ko "unite non ecrite par runuser"
grep -q "^runuser -u $ME -- install -d -m 700 $H/secagent/qualif$" "$T/calls.log" && ok "point de montage cree EN $ME" || ko "point de montage non cree par runuser"
first="$(grep '^apt-get' "$T/calls.log" | head -n 1)"
case "$first" in *" -s install "*) ok "simulation apt-get -s AVANT l'installation" ;; *) ko "pas de simulation en premier : $first" ;; esac
inst="$(grep '^apt-get' "$T/calls.log" | grep -v ' -s ')"
[ "$(printf '%s\n' "$inst" | grep -c .)" = 1 ] && ok "une seule installation" || ko "installations : $inst"
case "$inst" in *"NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive "*) ok "needrestart neutralise (MODE=l, SUSPEND=1), noninteractive" ;; *) ko "environnement apt-get : $inst" ;; esac
case "$inst" in *" install -y --no-install-recommends --no-upgrade moosefs-client") ok "--no-upgrade --no-install-recommends moosefs-client" ;; *) ko "arguments apt-get : $inst" ;; esac
[ -z "$(ls -A "$T/tmp")" ] && ok "fichier temporaire de l'unite retire" || ko "fichier temporaire restant : $(ls "$T/tmp")"
FAKE_APT_SIM="$T/sim-ok" expect_rc 0 "idempotent (2e passage)" "" qualif

reset_env; mkstubs 5.7.0 1.5.0 pasta present
expect_rc 0 "nominal prod, mfsmount present" "deja present" prod
grep -q '^apt-get' "$T/calls.log" 2>/dev/null && ko "apt-get appele alors que mfsmount est present" || ok "aucun apt-get si mfsmount present"
grep -q -- "-S $SUB/PROD " "$H/.config/systemd/user/secagent-prod-mfs.service" && ok "prod : sous-dossier PRIVATE/PROD" || ko "prod : sous-dossier inattendu"

# --- repertoires existants : jamais modifies ; lien refuse ; point de montage monte non touche ---------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta present
mkdir -m 755 "$H/.config"; mkdir -m 700 "$H/.config/systemd"
expect_rc 0 "~/.config 0755 et ~/.config/systemd 0700 existants" "" qualif
[ "$(stat -c %a "$H/.config")" = 755 ] && [ "$(stat -c %a "$H/.config/systemd")" = 700 ] && ok "modes des repertoires existants inchanges" \
  || ko "modes modifies : .config $(stat -c %a "$H/.config"), systemd $(stat -c %a "$H/.config/systemd")"
reset_env; mkdir -p "$T/ailleurs"; ln -s "$T/ailleurs" "$H/.config"
expect_rc 2 "~/.config lien symbolique refuse" "lien symbolique" qualif
reset_env; mkdir -p "$H/secagent/qualif"; chmod 755 "$H/secagent/qualif"
FAKE_MOUNTED="$H/secagent/qualif" expect_rc 0 "point de montage deja monte" "deja monte : non touche" qualif
[ "$(stat -c %a "$H/secagent/qualif")" = 755 ] && ok "montage actif : mode non modifie (pas de chmod sur le partage)" || ko "mode du montage modifie"
reset_env; mkdir -p "$H/secagent/qualif/state"
expect_rc 2 "point de montage non vide hors montage" "non vide hors montage" qualif
reset_env; mkdir -p "$H/secagent" "$T/ailleurs"; ln -s "$T/ailleurs" "$H/secagent/qualif"
expect_rc 2 "point de montage lien symbolique" "lien symbolique" qualif

# --- simulation apt : refus avant toute installation ---------------------------------------------------------------
sim_refus() { # $1 nom, $2 ligne de simulation, $3 motif
  reset_env; mkstubs 5.7.0 1.5.0 pasta absent
  printf 'Inst moosefs-client (4.59.2-1 MooseFS:26.04 [amd64])\n%s\n' "$2" > "$T/sim"
  FAKE_APT_SIM="$T/sim" expect_rc 2 "$1" "$3" qualif
  grep '^apt-get' "$T/calls.log" | grep -qv ' -s ' && ko "$1 : installation lancee malgre le refus" || ok "$1 : aucune installation"
}
sim_refus "simulation : retrait d'un paquet" "Remv docker-ce [5:29.0.1-1]" "retrait prevu"
sim_refus "simulation : mise a jour d'un paquet present" "Inst libc6 [2.43-2ubuntu2.3] (2.43-2ubuntu2.4 Ubuntu:26.04 [amd64])" "mise a jour d'un paquet present"
sim_refus "simulation : paquet hors liste" "Inst containerd (2.1.0-1 Ubuntu:26.04 [amd64])" "installation hors liste (containerd)"

# --- refus des preconditions et de la forme des variables (code 2) -------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta absent
expect_rc 2 "environnement invalide" "attendu qualif|prod" staging
expect_rc 2 "environnement absent" "REFUS:"
FAKE_EUID=1000 expect_rc 2 "non root" "a executer en root" qualif
XUID=4242 expect_rc 2 "uid du compte different" "attendu 4242" qualif
: > "$T/etc/subuid"; expect_rc 2 "subuid sans plage" "subuid" qualif; reset_env
printf '%s:100000:1000\n' "$ME" > "$T/etc/subgid"; expect_rc 2 "subgid trop petit (1000)" "minimum 65536" qualif; reset_env
XMASTER='1.2.3.4 -o allow_other' expect_rc 2 "MFS_MASTER avec espace" "MFS_MASTER=" qualif
XMASTER=$'mfs\nExecStartPre=/bin/true' expect_rc 2 "MFS_MASTER avec saut de ligne" "MFS_MASTER=" qualif
XSUBDIR='/CLAUDE_PROJETS/../PROD' expect_rc 2 "MFS_SUBDIR avec .." "MFS_SUBDIR=" qualif
XSUBDIR='/a b' expect_rc 2 "MFS_SUBDIR avec espace" "MFS_SUBDIR=" qualif
XUSER='Bad User' expect_rc 2 "NODE_USER invalide" "NODE_USER=" qualif
XHOME='home' expect_rc 2 "HOME_BASE relatif" "HOME_BASE=" qualif
mkstubs 4.2.1 1.5.0 pasta absent; expect_rc 2 "podman 4.2.1 < 4.3" "podman 4.2.1 < 4.3" qualif
mkstubs 4.3.0 1.5.0 pasta present; expect_rc 0 "podman 4.3.0 accepte (borne)" "" qualif; reset_env
mkstubs 5.7.0 1.1.0 pasta absent; expect_rc 2 "podman-compose 1.1.0 < 1.2" "podman-compose 1.1.0 < 1.2" qualif
mkstubs 5.7.0 1.5.0 pasta absent; rm "$T/bin/podman"; expect_rc 2 "podman absent" "jamais par ce script" qualif
if command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1; then
  echo "skip reseau rootless absent : pasta/slirp4netns present sur ce poste"
else
  mkstubs 5.7.0 1.5.0 none absent; expect_rc 2 "ni pasta ni slirp4netns" "reseau rootless" qualif
fi
reset_env; mkstubs 5.7.0 1.5.0 pasta absent; rm -f "$T/calls.log"
FAKE_EUID=1000 run qualif >/dev/null 2>&1
[ ! -e "$T/calls.log" ] && [ ! -e "$H/secagent" ] && ok "refus avant toute action (aucun appel, rien cree)" || ko "action executee malgre le refus"

# --- liste de refus de act() (code 3) -------------------------------------------------------------------------------
act_rc() { # $1 rc attendu, $2... commande
  local want="$1" rc; shift
  ( INSTALL_NODE_SOURCED=1; set +e; source "$S"; act "$@" ) >/dev/null 2>&1; rc=$?
  [ "$rc" = "$want" ] && ok "act $* (rc=$rc)" || ko "act $* (rc=$rc, attendu $want)"
}
act_rc 3 docker ps
act_rc 3 /usr/bin/docker info
act_rc 3 nerdctl ps
act_rc 3 buildah images
act_rc 3 kubectl get nodes
act_rc 3 k3s kubectl get pods
act_rc 3 systemctl restart docker
act_rc 3 systemctl stop containerd
act_rc 3 systemctl --user stop podman.socket
act_rc 3 systemctl --user try-restart secagent-qualif-mfs.service
act_rc 3 service rke2-server restart
act_rc 3 reboot
act_rc 3 shutdown -r now
act_rc 3 pkill -f mfsmount
act_rc 3 iptables -F
act_rc 3 nft flush ruleset
act_rc 3 ufw disable
act_rc 3 podman rm -f secagent
act_rc 3 podman stop secagent
act_rc 3 podman --remote kill secagent
act_rc 3 sh -c "docker ps"
act_rc 3 bash -ec true
act_rc 3 /bin/dash -c true
act_rc 3 eval true
act_rc 3 cat /opt/MFS/mfsmaster.cfg
act_rc 3 tee /etc/docker/daemon.json
act_rc 3 useradd secagent
act_rc 3 cp x /etc/sudoers.d/cyril
act_rc 3 sed -i s/a/b/ /etc/ssh/sshd_config
act_rc 3 mfschunkserver stop
act_rc 0 true loginctl enable-linger cyril
act_rc 0 true install -d -m 700 /home/cyril/secagent/qualif
act_rc 0 true runuser -u cyril -- install -m 644 /tmp/x /home/cyril/.config/systemd/user/secagent-qualif-mfs.service

# --- texte du script : aucune commande interdite hors de forbidden() et des commentaires ---------------------------
body="$(awk '/^forbidden\(\) \{/{skip=1} skip&&/^}/{skip=0; next} !skip' "$S" | grep -v '^[[:space:]]*#')"
if printf '%s\n' "$body" | grep -nE '(^|[^-[:alnum:]_])(docker|nerdctl|buildah|kubectl|k3s|rke2|containerd|crictl|helm|useradd|usermod|userdel|visudo|iptables|nft|ufw|reboot|shutdown|pkill|killall)([^-[:alnum:]_]|$)|/opt/MFS|daemon\.json|sudoers|sshd_config|allow_other.*fuse|/etc/fuse\.conf'; then
  ko "commande ou chemin interdit dans le corps du script (lignes ci-dessus)"
else
  ok "aucune commande interdite hors de la liste de refus"
fi
printf '%s\n' "$body" | grep -nE 'systemctl[^#]*(restart|stop|disable|mask)|podman (stop|rm|kill|rmi)' \
  && ko "arret/redemarrage de service ou de conteneur dans le script" || ok "aucun arret/redemarrage de service ni de conteneur"
inst_lines="$(printf '%s\n' "$body" | grep -nE 'apt-get[^#]*install' | grep -vE 'apt-get -s install')"
if [ -n "$inst_lines" ] && printf '%s\n' "$body" | grep -qE 'NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 *\\?$|NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 apt-get'; then
  ok "l'installation apt du texte porte NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1"
else
  ko "installation apt sans NEEDRESTART_* : $inst_lines"
fi

exit $bad
