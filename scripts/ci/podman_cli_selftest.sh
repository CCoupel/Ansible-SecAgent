#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Autotest de l'abstraction CONTAINER_CLI des scripts de qualif (#267, DEPLOYMENT/qualif/failover-test.sh) : routage
# des commandes `ctr` et `dc` vers le bon noeud (a -> A/srv3 ; b, enfant, minions -> B/srv4), stdin seulement quand il
# sert, commande distante passee mot a mot (printf %q), variables transmises a podman-compose, gardes. Faux `ssh` :
# aucun reseau, aucun noeud, aucun conteneur.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
F="$HERE/../../DEPLOYMENT/qualif/failover-test.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
bad=0
ok() { echo "ok   $*"; }
ko() { echo "KO   $*"; bad=1; }
# PATH HERMETIQUE : stubs de l'essai + liens vers une liste FERMEE d'utilitaires de base. Aucun autre binaire reel (podman,
# pasta, slirp4netns, mfsmount, docker, ssh... presents sur un runner) n'est visible : le resultat ne depend pas de la machine.
mksys() {
  mkdir -p "$T/sys"; local c p
  for c in bash sh env cat cp mv rm mkdir rmdir chmod install ln ls stat find awk sed grep sort head tail tr cut wc printf \
           mktemp timeout test dirname basename id uname sha256sum xargs diff date sleep cmp true false tee; do
    p="$(type -P "$c" 2>/dev/null)" || continue   # type -P : binaire reel (test, printf, true... sont aussi des builtins)
    case "$p" in /*) ln -sf "$p" "$T/sys/$c" ;; esac
  done
}
mksys
mkdir -p "$T/bin" "$T/k"; : > "$T/k/id"; : > "$T/k/kh"
# faux ssh : une ligne par appel = "<cible> | <commande distante> | stdin=<oui|non>"
cat > "$T/bin/ssh" <<EOF
#!/bin/bash
n=oui; tgt=""; cmd=""
while [ \$# -gt 0 ]; do case "\$1" in -n) n=non ;; -i|-o) shift ;; *) if [ -z "\$tgt" ]; then tgt="\$1"; else cmd="\$1"; fi ;; esac; shift; done
echo "\$tgt | \$cmd | stdin=\$n" >> "$T/ssh.log"
EOF
chmod +x "$T/bin/ssh"
P=/share/MFS/ROOT/essai/PRIVATE
ENVV=(PATH="$T/bin:$T/sys" CONTAINER_CLI=podman SECAGENT_PRIVATE_DIR="$P" CONTAINER_SSHKEY="$T/k/id"
      CONTAINER_KNOWN_HOSTS="$T/k/kh" TMPDIR="$T" C_A=secagent-qualif-a C_B=secagent-qualif-b C_CHILD=secagent-qualif-child)
run() { : > "$T/ssh.log"; env -i "${ENVV[@]}" "$@" bash -c 'source "$1"; set +e; eval "$CMD"' _ "$F" >/dev/null 2>&1; }
last() { cat "$T/ssh.log"; }
chk() { # $1 nom, $2 commande, $3 motif grep -E attendu (ensemble des appels), $4 nombre d'appels attendu
  CMD="$2" run CMD="$2"
  local n; n="$(grep -c . "$T/ssh.log")"
  if [ "$n" = "$4" ] && grep -qE -- "$3" "$T/ssh.log"; then ok "$1"; else ko "$1 (appels=$n) : $(last | tr '\n' '#')"; fi
}
A='cyril@192.168.1.213'; B='cyril@192.168.1.214'

# --- ctr : routage par conteneur, stdin ---------------------------------------------------------------------------
chk "ctr exec a -> noeud A, sans stdin" 'ctr exec secagent-qualif-a true' "^$A \\| podman exec secagent-qualif-a true  \\| stdin=non" 1
chk "ctr inspect b -> noeud B" 'ctr inspect -f x secagent-qualif-b' "^$B \\| podman inspect -f x secagent-qualif-b" 1
chk "ctr logs enfant -> noeud B" 'ctr logs secagent-qualif-child' "^$B \\| podman logs secagent-qualif-child" 1
chk "ctr run -i -> stdin transmis" 'ctr run --rm -i -v v:/x alpine true' "^$B \\| podman run --rm -i .* \\| stdin=oui" 1
chk "ctr load -> stdin transmis" 'ctr load' "^$B \\| podman load  \\| stdin=oui" 1
chk "CTR_NODE=A sans conteneur -> A" 'CTR_NODE=A ctr volume create v' "^$A \\| podman volume create v" 1
chk "quoting : espace et \$ passes mot a mot" "ctr exec secagent-qualif-a sh -c 'echo \$HOME x'" "^$A \\| podman exec secagent-qualif-a sh -c echo\\\\ \\\\\\\$HOME\\\\ x" 1
chk "cible ssh issue de CONTAINER_HOST_B" 'CONTAINER_HOST_B=ssh://cyril@10.0.0.9/run/user/1000/podman/podman.sock ctr ps' "^cyril@10.0.0.9 \\| podman ps" 1

# --- dc : repartition des services ---------------------------------------------------------------------------------
REL3="$P/QUALIF/srv3/cyril/secagent/release"; REL4="$P/QUALIF/srv4/cyril/secagent/release"
chk "dc up a b enfant -> A(a) + B(b, enfant)" 'dc up -d secagent-server-a secagent-server-b secagent-child' \
  "^$A .*env -C ${REL3//\//\\/} .*podman-compose -p secagent-qualif -f docker-compose.chain.yml -f docker-compose.hooks.yml -f docker-compose.podman.qualif.yml up -d secagent-server-a  " 2
grep -qE "^$B .*up -d secagent-server-b secagent-child  " "$T/ssh.log" && ok "dc up : B recoit b et l'enfant (et pas a)" || ko "dc up B : $(last | tr '\n' '#')"
grep -q "secagent-server-a" <(grep "^$B" "$T/ssh.log") && ko "a envoye au noeud B" || ok "a jamais envoye au noeud B"
chk "dc run a state init -> A seul" 'dc run --rm --no-deps secagent-server-a state init' "^$A .*run --rm --no-deps secagent-server-a state init" 1
chk "dc up sans service -> a sur A, b sur B" 'dc up -d' "^$A .*up -d secagent-server-a  " 2
grep -qE "^$B .*up -d secagent-server-b  " "$T/ssh.log" && ok "dc up sans service : b seul sur B (pas l'enfant ni les minions)" || ko "dc up B : $(last | tr '\n' '#')"
chk "dc down -> les deux noeuds" 'dc down' "podman-compose .* down  " 2
chk "dc --profile negative minion-negca -> B" 'dc --profile negative up -d --no-deps minion-negca' "^$B .*docker-compose.podman.qualif.yml --profile negative up -d --no-deps minion-negca" 1
chk "dc -f surcharge a b -> les deux, -f transmis" 'dc -f /x/o.yml up -d --no-deps --force-recreate secagent-server-a secagent-server-b' "^$A .*-f /x/o.yml up -d --no-deps --force-recreate secagent-server-a  " 2
chk "dc logs minion-root -> B" 'dc logs minion-root' "^$B .*logs minion-root" 1
chk "dc : variables transmises (QUALIF_PRIVATE_DIR, adresse de A, image)" 'SECAGENT_IMAGE=img:1 dc up -d secagent-server-a' "QUALIF_PRIVATE_DIR=${P//\//\\/}/QUALIF QUALIF_NODE_A_ADDR=192.168.1.213" 1
grep -q "SECAGENT_IMAGE=img:1" "$T/ssh.log" && ok "dc : SECAGENT_IMAGE transmise" || ko "dc : SECAGENT_IMAGE absente"
CMD='JWT_SECRET_KEY=secret-x dc up -d secagent-server-a' run CMD=x
grep -q "secret-x" "$T/ssh.log" && ko "dc : variable hors liste transmise" || ok "dc : seules les variables de la liste fermee sont transmises"

# --- gardes ----------------------------------------------------------------------------------------------------------
g() { # $1 nom, $2 rc attendu, $3 motif, puis variables
  local name="$1" want="$2" pat="$3" out rc; shift 3
  out="$(env -i "${ENVV[@]}" "$@" bash -c 'source "$1"; ctr ps' _ "$F" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && printf '%s' "$out" | grep -qF -- "$pat"; then ok "$name"; else ko "$name (rc=$rc) : $out"; fi
}
g "CONTAINER_CLI inconnu refuse" 2 "attendu docker ou podman" CONTAINER_CLI=nerdctl
g "PRIVATE hors /share/MFS/ROOT refuse" 2 "hors de /share/MFS/ROOT" SECAGENT_PRIVATE_DIR=/home/x/PRIVATE
g "CONTAINER_HOST mal forme refuse" 2 "attendu ssh://" CONTAINER_HOST_B=tcp://192.168.1.214:2375
g "CONTAINER_HOST avec injection refuse" 2 "attendu ssh://" 'CONTAINER_HOST_B=ssh://cyril@x;rm/run'
g "cle SSH absente refusee" 2 "cle SSH" CONTAINER_SSHKEY="$T/k/absente"
g "SECRETS_DIR different du partage refuse" 2 "SECRETS_DIR doit etre" SECRETS_DIR=/tmp/s
out="$(env -i "${ENVV[@]}" bash -c 'source "$1"; echo "$SECRET_OWNER_UID $QUALIF_TLS_DIR"' _ "$F" 2>&1)"
[ "$out" = "1000 $P/QUALIF/pki" ] && ok "Podman : SECRET_OWNER_UID=1000, TLS = PRIVATE/QUALIF/pki" || ko "defauts Podman : $out"
out="$(env -i PATH="$T/bin:$T/sys" SECAGENT_PRIVATE_DIR="$P" bash -c 'source "$1"; echo "$CONTAINER_CLI $SECRET_OWNER_UID"; docker() { echo "DOCKER $*"; }; ctr ps -a' _ "$F" 2>&1)"
[ "$out" = $'docker 10001\nDOCKER ps -a' ] && ok "Docker (defaut) : ctr = docker, SECRET_OWNER_UID=10001" || ko "mode docker : $out"
out="$(env -i "${ENVV[@]}" bash -c 'source "$1"; teardown_ok=0; guard_project' _ "$F" 2>&1)"; rc=$?
[ "$rc" = 0 ] && ok "guard_project : secagent-qualif accepte sous Podman" || ko "guard_project : $out"
out="$(env -i "${ENVV[@]}" PROJECT=secagent-chain bash -c 'source "$1"; guard_project' _ "$F" 2>&1)"; rc=$?
[ "$rc" = 2 ] && ok "guard_project : autre projet refuse sous Podman (hotes reels)" || ko "guard_project autre projet rc=$rc : $out"

exit $bad
