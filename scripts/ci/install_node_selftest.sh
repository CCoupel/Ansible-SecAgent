#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de DEPLOYMENT/podman/install-node.sh (#267) avec de faux `id`, `podman`, `podman-compose`, `loginctl`,
# `apt-get`... : sans root, sans noeud, sans reseau. Verifie les refus de preconditions (code 2), la liste de refus de
# act() (code 3), le chemin nominal (montage utilisateur sans allow_other, unite ecrite non activee, repertoire 0700) et
# l'absence de toute commande interdite dans le texte du script hors de la liste de refus.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../../DEPLOYMENT/podman/install-node.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
ME="$(id -un)"; MYUID="$(id -u)"; REAL_ID="$(command -v id)"

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
  local c; for c in newuidmap newgidmap loginctl apt-get; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n' "$c" "$T" > "$T/bin/$c"
  done
  chmod +x "$T/bin/"*
}
run() { # $@ arguments ; variables d'essai : home et subid dans $T
  env -i PATH="$T/bin:/usr/bin:/bin" NODE_USER="$ME" NODE_UID="${XUID:-$MYUID}" HOME_BASE="$T/home" SUBID_DIR="$T/etc" \
    FAKE_EUID="${FAKE_EUID:-0}" bash "$S" "$@"
}
expect_rc() { # $1 rc attendu, $2 nom, $3 motif attendu dans la sortie (optionnel), $4... arguments
  local want="$1" name="$2" pat="$3" out rc; shift 3
  out="$(run "$@" 2>&1)"; rc=$?
  [ "$rc" = "$want" ] && ok "$name (rc=$rc)" || ko "$name (rc=$rc, attendu $want) : $out"
  [ -z "$pat" ] || { printf '%s' "$out" | grep -qF -- "$pat" && ok "$name : message '$pat'" || ko "$name : message sans '$pat' : $out"; }
}
reset_env() {
  rm -rf "$T/home" "$T/etc" "$T/calls.log"; mkdir -p "$T/home/$ME" "$T/etc"
  printf '%s:100000:65536\n' "$ME" > "$T/etc/subuid"; printf '%s:100000:65536\n' "$ME" > "$T/etc/subgid"
}

# --- chemin nominal -------------------------------------------------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta absent
expect_rc 0 "nominal qualif" "NON activee" qualif
U="$T/home/$ME/.config/systemd/user/secagent-qualif-mfs.service"
[ -f "$U" ] && ok "unite --user ecrite" || ko "unite absente ($U)"
grep -q "^ExecStart=/usr/bin/mfsmount -f -n -H 192.168.1.231 -S /CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/QUALIF $T/home/$ME/secagent/qualif$" "$U" \
  && ok "ExecStart : master, sous-dossier PRIVATE/QUALIF, point de montage" || ko "ExecStart inattendu : $(grep ExecStart "$U")"
grep -qE '^ExecStart=.*(allow_other|-o)' "$U" && ko "allow_other (ou -o) dans ExecStart" || ok "pas d'allow_other dans ExecStart"
[ "$(stat -c %a "$T/home/$ME/secagent/qualif")" = 700 ] && ok "point de montage 0700" || ko "point de montage $(stat -c %a "$T/home/$ME/secagent/qualif")"
grep -q "^loginctl enable-linger $ME$" "$T/calls.log" && ok "linger active" || ko "linger non appele"
grep -q "^apt-get install -y --no-install-recommends moosefs-client$" "$T/calls.log" && ok "moosefs-client installe (absent)" || ko "apt-get moosefs-client non appele"
[ "$(grep -c '^apt-get' "$T/calls.log")" = 1 ] && ok "un seul apt-get" || ko "apt-get multiples"
expect_rc 0 "idempotent (2e passage)" "" qualif
reset_env; mkstubs 5.7.0 1.5.0 pasta present
expect_rc 0 "nominal prod, mfsmount present" "deja present" prod
grep -q '^apt-get' "$T/calls.log" 2>/dev/null && ko "apt-get appele alors que mfsmount est present" || ok "aucun apt-get si mfsmount present"
grep -q -- "-S /CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE/PROD " "$T/home/$ME/.config/systemd/user/secagent-prod-mfs.service" \
  && ok "prod : sous-dossier PRIVATE/PROD" || ko "prod : sous-dossier inattendu"

# --- refus des preconditions (code 2) -------------------------------------------------------------------------------
reset_env; mkstubs 5.7.0 1.5.0 pasta absent
expect_rc 2 "environnement invalide" "attendu qualif|prod" staging
expect_rc 2 "environnement absent" "REFUS:"
FAKE_EUID=1000 expect_rc 2 "non root" "a executer en root" qualif
XUID=4242 expect_rc 2 "uid du compte different" "attendu 4242" qualif
: > "$T/etc/subuid"; expect_rc 2 "subuid sans plage" "subuid" qualif; reset_env
mkstubs 4.2.1 1.5.0 pasta absent; expect_rc 2 "podman 4.2.1 < 4.3" "podman 4.2.1 < 4.3" qualif
mkstubs 4.3.0 1.5.0 pasta absent; expect_rc 0 "podman 4.3.0 accepte (borne)" "" qualif; reset_env
mkstubs 5.7.0 1.1.0 pasta absent; expect_rc 2 "podman-compose 1.1.0 < 1.2" "podman-compose 1.1.0 < 1.2" qualif
mkstubs 5.7.0 1.5.0 pasta absent; rm "$T/bin/podman"; expect_rc 2 "podman absent" "jamais par ce script" qualif
if command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1; then
  echo "skip reseau rootless absent : pasta/slirp4netns present sur ce poste"
else
  mkstubs 5.7.0 1.5.0 none absent; expect_rc 2 "ni pasta ni slirp4netns" "reseau rootless" qualif
fi
reset_env; mkstubs 5.7.0 1.5.0 pasta absent; rm -f "$T/calls.log"
FAKE_EUID=1000 run qualif >/dev/null 2>&1
[ ! -e "$T/calls.log" ] && [ ! -e "$T/home/$ME/secagent" ] && ok "refus avant toute action (aucun appel, rien cree)" || ko "action executee malgre le refus"

# --- liste de refus de act() (code 3) -------------------------------------------------------------------------------
act_rc() { # $1 rc attendu, $2... commande
  local want="$1" rc; shift
  ( INSTALL_NODE_SOURCED=1; set +e; source "$S"; act "$@" ) >/dev/null 2>&1; rc=$?
  [ "$rc" = "$want" ] && ok "act $* (rc=$rc)" || ko "act $* (rc=$rc, attendu $want)"
}
act_rc 3 docker ps
act_rc 3 /usr/bin/docker info
act_rc 3 kubectl get nodes
act_rc 3 k3s kubectl get pods
act_rc 3 systemctl restart docker
act_rc 3 systemctl stop containerd
act_rc 3 systemctl --user stop podman.socket
act_rc 3 podman rm -f secagent
act_rc 3 podman stop secagent
act_rc 3 podman --remote kill secagent
act_rc 3 systemctl --user try-restart secagent-qualif-mfs.service
act_rc 3 cat /opt/MFS/mfsmaster.cfg
act_rc 3 tee /etc/docker/daemon.json
act_rc 3 useradd secagent
act_rc 3 cp x /etc/sudoers.d/cyril
act_rc 3 sed -i s/a/b/ /etc/ssh/sshd_config
act_rc 3 mfschunkserver stop
act_rc 0 true loginctl enable-linger cyril
act_rc 0 true install -d -m 700 /home/cyril/secagent/qualif

# --- texte du script : aucune commande interdite hors de forbidden() et des commentaires ---------------------------
body="$(awk '/^forbidden\(\) \{/{skip=1} skip&&/^}/{skip=0; next} !skip' "$S" | grep -v '^[[:space:]]*#')"
if printf '%s\n' "$body" | grep -nE '(^|[^-[:alnum:]_])(docker|kubectl|k3s|rke2|containerd|crictl|helm|useradd|usermod|userdel|visudo)([^-[:alnum:]_]|$)|/opt/MFS|daemon\.json|sudoers|sshd_config|allow_other.*fuse|/etc/fuse\.conf'; then
  # tolere : les messages d'aide qui citent ces mots (aucun ici) ; toute occurrence est une regression
  ko "commande ou chemin interdit dans le corps du script (lignes ci-dessus)"
else
  ok "aucune commande interdite hors de la liste de refus"
fi
printf '%s\n' "$body" | grep -nE 'systemctl[^#]*(restart|stop|disable|mask)|podman (stop|rm|kill|rmi)' \
  && ko "arret/redemarrage de service ou de conteneur dans le script" || ok "aucun arret/redemarrage de service ni de conteneur"

exit $bad
