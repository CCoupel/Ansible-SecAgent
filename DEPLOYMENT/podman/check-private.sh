#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Garde FAIL-CLOSED avant le demarrage d'un conteneur secagent sur un noeud Podman (LOT-4 v3.0.6, #267) :
#
#   check-private.sh <qualif|prod> <srvX> [<manifeste epingle>]    0 si PRIVATE/<ENV> est accessible et conforme, 2 (REFUS:) sinon
#
# <manifeste epingle> (ExecStartPre de l'unite : %h/.config/secagent/<env>-<srvX>.sha256, hors partage, ecrit par
# verify-node-files.sh --pin) : bin/, release/ et systemd/ ne contiennent que des FICHIERS ORDINAIRES (lien symbolique,
# meme vers une copie identique, ou sous-dossier = REFUS) et leur liste EXACTE est celle du manifeste (fichier ou fichier
# cache en trop = REFUS, ex. un release/.env lu par podman-compose). Les
# empreintes sont verifiees juste avant par `sha256sum -c` du meme manifeste (ExecStartPre precedent).
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

env="${1:-}" node="${2:-}" pin="${3:-}"
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
# ca.key de la CA rangee a part (pki-ca/, #267) : jamais dans pki/, qui est monte EN ENTIER dans les conteneurs (/certs).
# pki/ ne contient QUE ca.crt, tls.crt, tls.key (noms seulement, aucun contenu lu) : toute autre entree (ca.key, cle de
# secours, sauvegarde...) serait montee dans /certs.
[ ! -e "$P/pki/ca.key" ] && [ ! -L "$P/pki/ca.key" ] || refuse "$P/pki/ca.key present : la cle de la CA doit etre dans $P/pki-ca/ (pki/ est monte dans les conteneurs)"
for f in "$P"/pki/* "$P"/pki/.[!.]*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  case "${f##*/}" in ca.crt|tls.crt|tls.key) [ -f "$f" ] && [ ! -L "$f" ] || refuse "$f n'est pas un fichier ordinaire" ;;
    *) refuse "$f : entree inattendue dans pki/ (seuls ca.crt, tls.crt, tls.key ; pki/ est monte sur /certs)" ;; esac
done
if [ -n "$pin" ]; then
  [[ $pin =~ ^/[A-Za-z0-9_./-]+$ && ! /$pin/ =~ /\.\./ ]] || refuse "manifeste epingle '$pin' : chemin absolu [A-Za-z0-9_./-] sans .. attendu"
  [ -f "$pin" ] && [ ! -L "$pin" ] || refuse "manifeste epingle $pin absent ou lien : relancer verify-node-files.sh --pin $env $node depuis le poste"
  B="$P/$node/cyril/secagent"
  # Liens symboliques : `sha256sum -c` les SUIT (un lien vers une copie identique passerait) ; la garde les refuse donc
  # ici, comme tout ce qui n'est pas un fichier ordinaire (find -P : liens jamais suivis, y compris pour les 3 dossiers).
  for d in bin release systemd; do
    [ -d "$B/$d" ] && [ ! -L "$B/$d" ] || refuse "$B/$d absent, non repertoire ou lien symbolique : ne pas demarrer"
  done
  odd="$(find "$B/bin" "$B/release" "$B/systemd" -mindepth 1 ! -type f -printf '  %y %p\n' 2>/dev/null)"
  if [ -n "$odd" ]; then
    printf '%s\n' "$odd" >&2
    refuse "entree(s) non fichier ordinaire (l = lien symbolique, d = dossier...) sous bin/, release/ ou systemd/ de $node : ne pas demarrer"
  fi
  want="$(cut -d' ' -f3- "$pin" | LC_ALL=C sort)"
  have="$(find "$B/bin" "$B/release" "$B/systemd" -mindepth 1 -print 2>/dev/null | LC_ALL=C sort)"
  if [ -z "$want" ] || [ "$want" != "$have" ]; then
    diffs="$(LC_ALL=C comm -3 <(printf '%s\n' "$want") <(printf '%s\n' "$have") | sed 's/^\t/  en trop : /; t; s/^/  manquant : /')"
    printf '%s\n' "$diffs" >&2
    refuse "fichiers de $node (bin/, release/, systemd/) differents du manifeste epingle $pin : ne pas demarrer"
  fi
fi
echo "PRIVATE/$E accessible ($t, uid $UIDX, 0700) ; fichiers de $node presents${pin:+, liste conforme au manifeste epingle}"
