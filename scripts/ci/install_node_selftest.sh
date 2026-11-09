#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de DEPLOYMENT/podman/install-node.sh, check-private.sh et prepare-node-files.sh (#267) avec de faux `id`, `podman`, `podman-compose`, `loginctl`,
# `runuser`, `df`... : sans root, sans noeud, sans reseau. Verifie les refus de preconditions et de forme des variables
# (code 2), l'espace disque (refus / ATTENTION), la delegation cgroup `memory`, la garde fail-closed check-private.sh
# (ecrite puis executee : chemin absent, sous-dossier manquant, modes, systeme de fichiers non FUSE), la liste de refus
# de act() (code 3), les repertoires existants non modifies, et l'absence de tout apt/mfsmount/commande interdite.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../../DEPLOYMENT/podman/install-node.sh"
CP="$HERE/../../DEPLOYMENT/podman/check-private.sh"
PREP="$HERE/../../DEPLOYMENT/podman/prepare-node-files.sh"
T="$(mktemp -d)"; trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
ME="$(id -un)"; MYUID="$(id -u)"; REAL_ID="$(command -v id)"
FST="$(stat -f -c %T "$T")"   # type reel du systeme de fichiers de l'essai (accepte par la garde via SECAGENT_PRIVATE_FSTYPES)

mkstubs() { # $1 version podman, $2 version podman-compose, $3 reseau (pasta|none)
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
  local c; for c in newuidmap newgidmap loginctl apt-get apt dpkg mfsmount; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n' "$c" "$T" > "$T/bin/$c"
  done
  cat > "$T/bin/runuser" <<EOF
#!/bin/sh
echo "runuser \$*" >> "$T/calls.log"
while [ "\$#" -gt 0 ] && [ "\$1" != -- ]; do shift; done; shift
exec "\$@"
EOF
  # faux df : "<avail Kio> <pcent>%" de \$FAKE_DF (defaut : 40 Gio libres, 58 %)
  printf '#!/bin/sh\necho "Avail Use%%"\necho "${FAKE_DF:-41943040 58%%}"\n' > "$T/bin/df"
  chmod +x "$T/bin/"*
}
run() { # $@ arguments
  local extra=()
  [ -z "${XPRIV:-}" ] || extra+=("PRIVATE_ROOT=$XPRIV")
  [ -z "${XCG:-}" ] || extra+=("CGROUP_ROOT=$XCG")
  [ -z "${XFREE:-}" ] || extra+=("MIN_FREE_GB=$XFREE")
  env -i PATH="$T/bin:/usr/bin:/bin" NODE_USER="${XUSER:-$ME}" NODE_UID="${XUID:-$MYUID}" HOME_BASE="${XHOME:-$T/home}" \
    SUBID_DIR="$T/etc" CGROUP_ROOT="$T/cg" PRIVATE_ROOT="$T/private" TMPDIR="$T/tmp" FAKE_EUID="${FAKE_EUID:-0}" \
    FAKE_DF="${FAKE_DF:-41943040 58%}" SECAGENT_PRIVATE_FSTYPES="${XFST:-$FST}" NODE_NAME="${XNODE:-srv3}" "${extra[@]}" bash "$S" "$@"
}
expect_rc() { # $1 rc attendu, $2 nom, $3 motif attendu dans la sortie (optionnel), $4... arguments
  local want="$1" name="$2" pat="$3" out rc; shift 3
  out="$(run "$@" 2>&1)"; rc=$?
  [ "$rc" = "$want" ] && ok "$name (rc=$rc)" || ko "$name (rc=$rc, attendu $want) : $out"
  [ -z "$pat" ] || { printf '%s' "$out" | grep -qF -- "$pat" && ok "$name : message '$pat'" || ko "$name : message sans '$pat' : $out"; }
}
reset_env() {
  chmod -R u+rwx "$T/home" "$T/private" 2>/dev/null
  rm -rf "$T/home" "$T/etc" "$T/calls.log" "$T/tmp" "$T/cg" "$T/private"
  mkdir -p "$T/home/$ME" "$T/etc" "$T/tmp" "$T/cg/user.slice/user-$MYUID.slice/user@$MYUID.service"
  printf '%s:100000:65536\n' "$ME" > "$T/etc/subuid"; printf '%s:100000:65536\n' "$ME" > "$T/etc/subgid"
  echo "cpu memory pids" > "$T/cg/user.slice/user-$MYUID.slice/user@$MYUID.service/cgroup.controllers"
  mkdir -m 700 "$T/private"
  local d; for d in QUALIF QUALIF/state QUALIF/state/root QUALIF/state/child QUALIF/secrets QUALIF/pki \
                    PROD PROD/state PROD/state/root PROD/secrets PROD/pki; do mkdir -m 700 "$T/private/$d"; done
  # fichiers de deploiement des noeuds, prepares DEPUIS LE POSTE (prepare-node-files.sh)
  for d in "qualif srv3" "qualif srv4" "prod srv1"; do
    # shellcheck disable=SC2086
    SECAGENT_PRIVATE_DIR="$T/private" bash "$PREP" $d >/dev/null || ko "prepare-node-files $d"
  done
}
H="$T/home/$ME"
G="$T/private/QUALIF/srv3/cyril/secagent/bin/check-private.sh"

# --- chemin nominal -------------------------------------------------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta
expect_rc 0 "nominal qualif srv3" "fichiers de srv3 presents" qualif srv3
[ "$(stat -c %a "$H/.config/systemd/user" 2>/dev/null)" = 700 ] && ok "~/.config/systemd/user cree 0700" || ko "~/.config/systemd/user : $(stat -c %a "$H/.config/systemd/user" 2>/dev/null)"
[ ! -e "$H/secagent" ] && ok "aucun ~/secagent sur le noeud (fichiers centralises sur le partage)" || ko "~/secagent cree sur le noeud"
[ "$(find "$H" -mindepth 1 | sort | tr '\n' ' ')" = "$H/.config $H/.config/systemd $H/.config/systemd/user " ] \
  && ok "seul ~/.config/systemd/user est cree dans le home" || ko "home : $(find "$H" -mindepth 1 | tr '\n' ' ')"
grep -q "^loginctl enable-linger $ME$" "$T/calls.log" && ok "linger active" || ko "linger non appele"
grep -qF "runuser -u $ME -- env SECAGENT_PRIVATE_ROOT=$T/private SECAGENT_NODE_UID=$MYUID SECAGENT_NODE_NAME=srv3 $G qualif srv3" "$T/calls.log" \
  && ok "garde du partage executee EN $ME" || ko "garde non executee : $(grep runuser "$T/calls.log")"
grep -E "install -m|cp |tee " "$T/calls.log" && ko "copie de fichier sur le noeud" || ok "aucune copie de fichier sur le noeud (seuls des repertoires ~/.config)"
grep -qE '^(apt-get|apt|dpkg|mfsmount) ' "$T/calls.log" && ko "apt/dpkg/mfsmount appele" || ok "aucun apt, dpkg ni mfsmount"
[ -z "$(ls -A "$T/tmp")" ] && ok "fichier temporaire retire" || ko "fichier temporaire restant : $(ls "$T/tmp")"
expect_rc 0 "idempotent (2e passage)" "" qualif srv3
reset_env; mkstubs 5.7.0 1.5.0 pasta
rm -rf "$T/private/QUALIF/state/child"
XNODE=srv1 expect_rc 0 "prod srv1 : state/child non exige" "PRIVATE/PROD accessible" prod srv1
rm -f "$T/calls.log"
XNODE=srv4 expect_rc 2 "noeud courant srv4 mais argument srv3" "different de 'srv3'" qualif srv3
[ ! -e "$T/calls.log" ] && ok "noeud different : refus AVANT toute action (pas de linger)" || ko "noeud different : actions lancees ($(cat "$T/calls.log"))"
expect_rc 2 "couple incoherent qualif srv1" "attendu qualif srv3|srv4" qualif srv1
expect_rc 2 "noeud absent" "attendu qualif srv3|srv4" qualif
XNODE=srv2 expect_rc 2 "prod srv2 : fichiers non prepares" "lancer d'abord prepare-node-files.sh prod srv2" prod srv2
reset_env; mkstubs 5.7.0 1.5.0 pasta; chmod 755 "$G"
expect_rc 2 "garde du partage en 0755" "attendu uid $MYUID mode 700" qualif srv3
reset_env; mkstubs 5.7.0 1.5.0 pasta; mv "$G" "$G.orig"; ln -s "$G.orig" "$G"
expect_rc 2 "garde du partage : lien symbolique" "lien symbolique" qualif srv3

# --- disque, cgroup -------------------------------------------------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta
FAKE_DF='15728640 72%' expect_rc 0 "disque 72 % (srv3) : avertissement" "ATTENTION: $H occupe a 72 %" qualif srv3
FAKE_DF='3145728 97%' expect_rc 2 "disque : 3 Gio libres < 5" "minimum 5 Gio" qualif srv3
FAKE_DF='3145728 97%' XFREE=2 expect_rc 0 "disque : seuil MIN_FREE_GB ajustable" "" qualif srv3
FAKE_DF='n/a' expect_rc 2 "disque : sortie df inattendue" "sortie inattendue" qualif srv3
reset_env; mkstubs 5.7.0 1.5.0 pasta
echo "cpu pids" > "$T/cg/user.slice/user-$MYUID.slice/user@$MYUID.service/cgroup.controllers"
expect_rc 2 "cgroup memory non delegue" "limites memoire des conteneurs seraient ignorees" qualif srv3
rm -f "$T/cg/user.slice/user-$MYUID.slice/user@$MYUID.service/cgroup.controllers"
expect_rc 2 "cgroup.controllers absent" "gestionnaire systemd --user" qualif srv3

# --- garde fail-closed PRIVATE/<ENV> --------------------------------------------------------------------------------
guard_refus() { # $1 nom, $2 preparation (eval), $3 motif
  reset_env; mkstubs 5.7.0 1.5.0 pasta
  eval "$2"
  expect_rc 2 "$1" "$3" qualif srv3
}
guard_refus "garde : PRIVATE/QUALIF absent (autofs non monte)" 'rm -rf "$T/private/QUALIF"' "inaccessible"
guard_refus "garde : state/child manquant" 'rmdir "$T/private/QUALIF/state/child"' "state/child absent"
guard_refus "garde : secrets en 0755" 'chmod 755 "$T/private/QUALIF/secrets"' "secrets en 755, attendu 0700"
guard_refus "garde : racine QUALIF en 0755" 'chmod 755 "$T/private/QUALIF"' "QUALIF en 755"
guard_refus "garde : pki lien symbolique" 'rmdir "$T/private/QUALIF/pki"; mkdir -m 700 "$T/autre"; ln -s "$T/autre" "$T/private/QUALIF/pki"' "pki absent, non repertoire ou lien"
reset_env; mkstubs 5.7.0 1.5.0 pasta
XFST=fuseblk expect_rc 2 "garde : systeme de fichiers non FUSE (repertoire local)" "attendu MooseFS/FUSE" qualif srv3
guard_refus "garde : dossier du noeud srv3 manquant" 'chmod -R u+rwx "$T/private/QUALIF/srv3"; mv "$T/private/QUALIF/srv3/cyril" "$T/cyril-ailleurs"; mkdir -p "$T/private/QUALIF/srv3/cyril/secagent/bin"; chmod 700 "$T/private/QUALIF/srv3/cyril" "$T/private/QUALIF/srv3/cyril/secagent" "$T/private/QUALIF/srv3/cyril/secagent/bin"; install -m 700 "$CP" "$G"; chmod 755 "$T/private/QUALIF/srv3/cyril"' "cyril en 755, attendu 0700"

# garde executee seule (comme ExecStartPre) : couple, noeud courant, dossiers du noeud
reset_env
gd() { env -i PATH=/usr/bin:/bin SECAGENT_PRIVATE_ROOT="$T/private" SECAGENT_NODE_UID="$MYUID" SECAGENT_PRIVATE_FSTYPES="${XFST:-$FST}" "$@"; }
out="$(gd SECAGENT_NODE_NAME=srv3 bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 0 ] && ok "garde seule : qualif srv3 conforme" || ko "garde seule qualif srv3 rc=$rc : $out"
out="$(gd SECAGENT_NODE_NAME=srv3.lan bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 0 ] && ok "garde seule : nom de noeud avec domaine accepte (srv3.lan)" || ko "garde srv3.lan rc=$rc : $out"
out="$(gd SECAGENT_NODE_NAME=srv4 bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule : noeud courant srv4 != srv3 refuse" || ko "garde srv4/srv3 rc=$rc : $out"
out="$(gd SECAGENT_NODE_NAME=srv1 bash "$G" qualif srv1 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule : couple qualif srv1 refuse" || ko "garde qualif srv1 rc=$rc : $out"
out="$(gd SECAGENT_NODE_NAME=srv3 bash "$G" staging srv3 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule : environnement invalide refuse" || ko "garde staging rc=$rc : $out"
out="$(gd SECAGENT_NODE_NAME=srv2 bash "$G" prod srv2 2>&1)"; rc=$?
[ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "PROD/srv2 absent" && ok "garde seule : fichiers de srv2 absents refuses" || ko "garde prod srv2 rc=$rc : $out"
chmod 755 "$T/private/QUALIF/srv3/cyril/secagent"
out="$(gd SECAGENT_NODE_NAME=srv3 bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule : srv3/cyril/secagent en 0755 refuse" || ko "garde secagent 0755 rc=$rc : $out"
chmod 700 "$T/private/QUALIF/srv3/cyril/secagent"
out="$(gd SECAGENT_PRIVATE_ROOT=relatif SECAGENT_NODE_NAME=srv3 bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule : SECAGENT_PRIVATE_ROOT relatif refuse" || ko "garde racine relative rc=$rc : $out"
out="$(env -i PATH=/usr/bin:/bin SECAGENT_PRIVATE_ROOT="$T/private" SECAGENT_NODE_UID="$MYUID" SECAGENT_NODE_NAME=srv3 bash "$G" qualif srv3 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "garde seule, types par defaut (fuseblk fuse) : $FST refuse" || ko "garde types par defaut rc=$rc : $out"

# --- prepare-node-files.sh (poste) --------------------------------------------------------------------------------
reset_env
for d in "" /cyril /cyril/secagent /cyril/secagent/bin /cyril/secagent/release /cyril/secagent/systemd; do
  [ "$(stat -c %a "$T/private/QUALIF/srv4$d")" = 700 ] || ko "prepare : QUALIF/srv4$d $(stat -c %a "$T/private/QUALIF/srv4$d")"
done && ok "prepare : arborescence srv4/cyril/secagent/{bin,release,systemd} en 0700"
cmp -s "$CP" "$T/private/QUALIF/srv4/cyril/secagent/bin/check-private.sh" && [ "$(stat -c %a "$T/private/QUALIF/srv4/cyril/secagent/bin/check-private.sh")" = 700 ] \
  && ok "prepare : garde copiee a l'identique (0700)" || ko "prepare : garde differente ou mode"
chmod 750 "$T/private/QUALIF/srv4/cyril/secagent/release"
SECAGENT_PRIVATE_DIR="$T/private" bash "$PREP" qualif srv4 >/dev/null 2>&1 && [ "$(stat -c %a "$T/private/QUALIF/srv4/cyril/secagent/release")" = 750 ] \
  && ok "prepare : idempotent, existant non modifie" || ko "prepare : existant modifie ou echec"
prep_rc() { # $1 rc, $2 nom, $3... arguments (variables d'environnement prefixees possibles)
  local want="$1" name="$2" rc; shift 2
  env "$@" >/dev/null 2>&1; rc=$?
  [ "$rc" = "$want" ] && ok "prepare : $name (rc=$rc)" || ko "prepare : $name (rc=$rc, attendu $want)"
}
prep_rc 2 "couple qualif srv1 refuse" SECAGENT_PRIVATE_DIR="$T/private" bash "$PREP" qualif srv1
prep_rc 2 "noeud absent refuse" SECAGENT_PRIVATE_DIR="$T/private" bash "$PREP" prod
prep_rc 2 "racine PRIVATE absente refusee" SECAGENT_PRIVATE_DIR="$T/absent" bash "$PREP" prod srv2
prep_rc 2 "racine PRIVATE relative refusee" SECAGENT_PRIVATE_DIR="private" bash "$PREP" prod srv2
[ ! -e "$T/absent" ] && ok "prepare : racine absente jamais creee" || ko "prepare : racine creee"
ln -s "$T/ailleurs-srv2" "$T/private/PROD/srv2"
prep_rc 2 "dossier du noeud lien symbolique refuse" SECAGENT_PRIVATE_DIR="$T/private" bash "$PREP" prod srv2

# --- repertoires existants : jamais modifies ; liens refuses --------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta
mkdir -m 755 "$H/.config"; mkdir -m 700 "$H/.config/systemd"
expect_rc 0 "~/.config 0755 et ~/.config/systemd 0700 existants" "" qualif srv3
[ "$(stat -c %a "$H/.config")" = 755 ] && [ "$(stat -c %a "$H/.config/systemd")" = 700 ] && ok "modes des repertoires existants inchanges" \
  || ko "modes modifies : .config $(stat -c %a "$H/.config"), systemd $(stat -c %a "$H/.config/systemd")"
reset_env; mkdir -p "$T/ailleurs"; ln -s "$T/ailleurs" "$H/.config"
expect_rc 2 "~/.config lien symbolique refuse" "lien symbolique" qualif srv3

# --- refus des preconditions et de la forme des variables (code 2) -------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta
expect_rc 2 "environnement invalide" "attendu qualif srv3|srv4" staging srv3
expect_rc 2 "environnement absent" "REFUS:"
FAKE_EUID=1000 expect_rc 2 "non root" "a executer en root" qualif srv3
XUID=4242 expect_rc 2 "uid du compte different" "attendu 4242" qualif srv3
: > "$T/etc/subuid"; expect_rc 2 "subuid sans plage" "subuid" qualif srv3; reset_env
printf '%s:100000:1000\n' "$ME" > "$T/etc/subgid"; expect_rc 2 "subgid trop petit (1000)" "minimum 65536" qualif srv3; reset_env
XPRIV='private' expect_rc 2 "PRIVATE_ROOT relatif" "PRIVATE_ROOT=" qualif srv3
XPRIV='/a/../PROD' expect_rc 2 "PRIVATE_ROOT avec .." "PRIVATE_ROOT=" qualif srv3
XPRIV=$'/a\nset -x' expect_rc 2 "PRIVATE_ROOT avec saut de ligne" "PRIVATE_ROOT=" qualif srv3
XCG='/sys/fs/cgroup x' expect_rc 2 "CGROUP_ROOT avec espace" "CGROUP_ROOT=" qualif srv3
XFREE='5G' expect_rc 2 "MIN_FREE_GB invalide" "MIN_FREE_GB=" qualif srv3
XUSER='Bad User' expect_rc 2 "NODE_USER invalide" "NODE_USER=" qualif srv3
XHOME='home' expect_rc 2 "HOME_BASE relatif" "HOME_BASE=" qualif srv3
mkstubs 4.2.1 1.5.0 pasta; expect_rc 2 "podman 4.2.1 < 4.3" "podman 4.2.1 < 4.3" qualif srv3
mkstubs 4.3.0 1.5.0 pasta; expect_rc 0 "podman 4.3.0 accepte (borne)" "" qualif srv3; reset_env
mkstubs 5.7.0 1.1.0 pasta; expect_rc 2 "podman-compose 1.1.0 < 1.2" "podman-compose 1.1.0 < 1.2" qualif srv3
mkstubs 5.7.0 1.5.0 pasta; rm "$T/bin/podman"; expect_rc 2 "podman absent" "jamais par ce script" qualif srv3
if command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1; then
  echo "skip reseau rootless absent : pasta/slirp4netns present sur ce poste"
else
  mkstubs 5.7.0 1.5.0 none; expect_rc 2 "ni pasta ni slirp4netns" "reseau rootless" qualif srv3
fi
reset_env; mkstubs 5.7.0 1.5.0 pasta; rm -f "$T/calls.log"
FAKE_EUID=1000 run qualif srv3 >/dev/null 2>&1
[ ! -e "$T/calls.log" ] && [ ! -e "$H/secagent" ] && ok "refus avant toute action (aucun appel, rien cree)" || ko "action executee malgre le refus"

# --- liste de refus de act() (code 3) -------------------------------------------------------------------------------
act_rc() { # $1 rc attendu, $2... commande
  local want="$1" rc; shift
  ( INSTALL_NODE_SOURCED=1; set +e; source "$S"; act "$@" ) >/dev/null 2>&1; rc=$?
  [ "$rc" = "$want" ] && ok "act $* (rc=$rc)" || ko "act $* (rc=$rc, attendu $want)"
}
act_rc 3 apt-get install -y moosefs-client
act_rc 3 env DEBIAN_FRONTEND=noninteractive apt-get install x
act_rc 3 apt install x
act_rc 3 dpkg -i x.deb
act_rc 3 snap install x
act_rc 3 mfsmount -H 192.168.1.231 /mnt
act_rc 3 docker ps
act_rc 3 /usr/bin/docker info
act_rc 3 nerdctl ps
act_rc 3 buildah images
act_rc 3 kubectl get nodes
act_rc 3 k3s kubectl get pods
act_rc 3 systemctl restart docker
act_rc 3 systemctl stop containerd
act_rc 3 systemctl --user stop podman.socket
act_rc 3 systemctl --user try-restart x.service
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
act_rc 0 true runuser -u cyril -- install -m 700 /tmp/x /home/cyril/secagent/bin/check-private.sh
act_rc 0 true runuser -u cyril -- env SECAGENT_PRIVATE_ROOT=/share/MFS/ROOT/x/PRIVATE /share/MFS/ROOT/x/PRIVATE/QUALIF/srv3/cyril/secagent/bin/check-private.sh qualif srv3

# --- texte du script : aucune commande interdite hors de forbidden() et des commentaires ---------------------------
body="$(awk '/^forbidden\(\) \{/{skip=1} skip&&/^}/{skip=0; next} !skip' "$S" | grep -v '^[[:space:]]*#')"
if printf '%s\n' "$body" | grep -nE '(^|[^-[:alnum:]_])(apt|apt-get|dpkg|snap|mfsmount|moosefs-client|docker|nerdctl|buildah|kubectl|k3s|rke2|containerd|crictl|helm|useradd|usermod|userdel|visudo|iptables|nft|ufw|reboot|shutdown|pkill|killall)([^-[:alnum:]_]|$)|/opt/MFS|daemon\.json|sudoers|sshd_config|/etc/fuse\.conf'; then
  ko "commande ou chemin interdit dans le corps du script (lignes ci-dessus)"
else
  ok "aucun apt/mfsmount ni commande interdite hors de la liste de refus"
fi
printf '%s\n' "$body" | grep -nE 'systemctl[^#]*(restart|stop|disable|mask)|podman (stop|rm|kill|rmi)' \
  && ko "arret/redemarrage de service ou de conteneur dans le script" || ok "aucun arret/redemarrage de service ni de conteneur"

exit $bad
