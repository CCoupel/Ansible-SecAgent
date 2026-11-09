#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Garde FAIL-CLOSED avant le demarrage d'un conteneur secagent sur un noeud Podman (LOT-4 v3.0.6, #267) :
#
#   check-private.sh <qualif|prod> <srvX>    0 si PRIVATE/<ENV> est accessible et conforme, 2 (REFUS:) sinon
#
# Copiee depuis le poste (prepare-node-files.sh) dans PRIVATE/<ENV>/<srvX>/cyril/secagent/bin/ ; executee par
# install-node.sh puis en ExecStartPre= des unites --user des conteneurs (T44/T45). Lit uniquement des metadonnees
# (stat), aucun contenu. Le serveur ne doit JAMAIS demarrer sur un repertoire local vide : refus si PRIVATE/<ENV>
# est inaccessible (autofs /share/MFS/ROOT non monte, master MooseFS injoignable : borne a 30 s), hors FUSE, d'un
# autre uid que 1000, pas en 0700, ou si un sous-dossier requis manque, ou si le noeud courant n'est pas <srvX>.
# Variables (essais) : SECAGENT_PRIVATE_ROOT (racine PRIVATE vue du noeud), SECAGENT_PRIVATE_FSTYPES (fuseblk fuse),
#   SECAGENT_NODE_UID (1000), SECAGENT_NODE_NAME (nom court du noeud, defaut `uname -n` sans domaine).
set -u
refuse() { echo "REFUS: $*" >&2; exit 2; }

ROOT="${SECAGENT_PRIVATE_ROOT:-/share/MFS/ROOT/CLAUDE_PROJETS/PROJETS/PRO/Ansible_SecAgent/PRIVATE}"
UIDX="${SECAGENT_NODE_UID:-1000}"
[[ $ROOT =~ ^/[A-Za-z0-9_./-]*$ && ! /$ROOT/ =~ /\.\./ ]] || refuse "SECAGENT_PRIVATE_ROOT='$ROOT' invalide"
[[ $UIDX =~ ^[0-9]{1,10}$ ]] || refuse "SECAGENT_NODE_UID='$UIDX' invalide"

env="${1:-}" node="${2:-}"
case "$env:$node" in
  qualif:srv3|qualif:srv4) E=QUALIF; SUBS="state/root state/child secrets pki" ;;
  prod:srv1|prod:srv2) E=PROD; SUBS="state/root secrets pki" ;;
  *) refuse "couple '$env $node' : attendu qualif srv3|srv4 ou prod srv1|srv2" ;;
esac
here="${SECAGENT_NODE_NAME:-$(uname -n)}"; here="${here%%.*}"
[ "$here" = "$node" ] || refuse "noeud courant '$here' different de '$node' : fichiers d'un autre noeud"

P="$ROOT/$E"
# acces = declenchement de l'autofs ; borne a 30 s (master injoignable : refus plutot qu'attente infinie)
timeout 30 test -d "$P" || refuse "$P inaccessible (autofs /share/MFS/ROOT non monte ou MooseFS injoignable)"
[ ! -L "$P" ] || refuse "$P est un lien symbolique"
t="$(stat -f -c %T "$P")"
case " ${SECAGENT_PRIVATE_FSTYPES:-fuseblk fuse} " in
  *" $t "*) ;;
  *) refuse "$P sur un systeme de fichiers '$t' (attendu MooseFS/FUSE) : repertoire local ?" ;;
esac
# shellcheck disable=SC2086   # SUBS : liste de mots fixe ci-dessus
for d in "" $SUBS "$node" "$node/cyril" "$node/cyril/secagent"; do
  p="$P${d:+/$d}"
  [ -d "$p" ] && [ ! -L "$p" ] || refuse "$p absent, non repertoire ou lien"
  [ "$(stat -c %u "$p")" = "$UIDX" ] || refuse "$p n'appartient pas a l'uid $UIDX"
  [ "$(stat -c %a "$p")" = 700 ] || refuse "$p en $(stat -c %a "$p"), attendu 0700"
done
# ca.key de la CA rangee a part (pki-ca/, #267) : jamais dans pki/, qui est monte dans les conteneurs (/certs)
[ ! -e "$P/pki/ca.key" ] && [ ! -L "$P/pki/ca.key" ] || refuse "$P/pki/ca.key present : la cle de la CA doit etre dans $P/pki-ca/ (pki/ est monte dans les conteneurs)"
echo "PRIVATE/$E accessible ($t, uid $UIDX, 0700) ; fichiers de $node presents"
