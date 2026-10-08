#!/usr/bin/env bash
# Preflight des fichiers de secrets de PRODUCTION (#196, v3.0.4) : a lancer AVANT `docker compose up`, sur CHAQUE hote.
#
#   ./preflight-secrets.sh [--child]            verifie (code 0 = OK, 1 = au moins une erreur, tout est liste)
#   sudo ./preflight-secrets.sh --fix [--child] corrige proprietaire (10001:10001) et mode (0400) des fichiers presents
#   printf '%s' "$VALEUR" | sudo ./preflight-secrets.sh --write jwt_secret_key
#                                               cree/remplace le secret NOM depuis stdin (0400, proprietaire 10001),
#                                               sans jamais l'afficher ; NOM = jwt_secret_key | admin_token |
#                                               rsa_master_key | repeater_upstream_token
#
# Pourquoi : hors Swarm, Compose monte un `secrets: file:` en BIND MOUNT du fichier de l'HOTE et IGNORE uid/gid/mode.
# Le conteneur tourne en UID 10001 et le serveur (secretenv) refuse tout fichier de secret lisible par le groupe ou les
# autres (il n'accepte que 0400/0600) : le fichier doit donc APPARTENIR a l'UID 10001 avec le mode 0400 (ou 0600).
# Sinon le serveur sort au demarrage (« permission denied » ou « permissions too open ») et redemarre en boucle.
#
# Variables : SECRETS_DIR (defaut ./secrets, comme le Compose), ROOT_LINK_KEY_FILE (enfant : cle publique racine),
#   SECRET_OWNER_UID (defaut 10001, uniquement pour les tests).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OWNER="${SECRET_OWNER_UID:-10001}"
DIR="${SECRETS_DIR:-./secrets}"
ERR=0; MODE=check; CHILD=0; WRITE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --child) CHILD=1 ;;
    --fix) MODE=fix ;;
    --write) MODE=write; WRITE="${2:-}"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "argument inconnu: $1" >&2; exit 2 ;;
  esac
  shift
done
bad() { echo "ERREUR: $*" >&2; ERR=1; }
SECRETS=(jwt_secret_key admin_token rsa_master_key)
[ "$CHILD" = 1 ] && SECRETS+=(repeater_upstream_token)

if [ "$MODE" = write ]; then
  case "$WRITE" in jwt_secret_key|admin_token|rsa_master_key|repeater_upstream_token) ;; *) echo "NOM invalide: '$WRITE'" >&2; exit 2 ;; esac
  [ -d "$DIR" ] || { mkdir -p "$DIR" && chmod 0700 "$DIR"; } || { echo "impossible de creer $DIR" >&2; exit 1; }
  [ -L "$DIR/$WRITE" ] && { echo "$DIR/$WRITE est un lien symbolique : refus" >&2; exit 1; }
  tmp="$DIR/.$WRITE.tmp.$$"
  ( umask 077; cat > "$tmp" ) || { rm -f "$tmp"; exit 1; }
  [ -s "$tmp" ] || { rm -f "$tmp"; echo "valeur vide : refus" >&2; exit 1; }
  chown "$OWNER:$OWNER" "$tmp" 2>/dev/null || { rm -f "$tmp"; echo "chown $OWNER:$OWNER impossible (lancer avec sudo)" >&2; exit 1; }
  chmod 0400 "$tmp" && mv -f "$tmp" "$DIR/$WRITE" || { rm -f "$tmp"; exit 1; }
  echo "secret $WRITE ecrit (0400, proprietaire $OWNER), valeur non affichee"
  exit 0
fi

[ -f "$HERE/prod.env" ] && echo "AVERTISSEMENT: prod.env existe : il n'est plus lu par Compose (v3.0.4). Les secrets sont des fichiers ; supprimer prod.env apres migration (une variable directe en plus d'un *_FILE = refus de demarrer)." >&2
[ -d "$DIR" ] || { echo "ERREUR: $DIR absent (SECRETS_DIR)" >&2; exit 1; }

for n in "${SECRETS[@]}"; do
  f="$DIR/$n"
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then bad "$f absent (docker creerait un REPERTOIRE a sa place)"; continue; fi
  if [ -L "$f" ]; then bad "$f est un lien symbolique (refuse par le serveur)"; continue; fi
  if [ ! -f "$f" ]; then bad "$f n'est pas un fichier regulier"; continue; fi
  if [ "$MODE" = fix ]; then
    chown "$OWNER:$OWNER" "$f" 2>/dev/null || bad "chown $OWNER:$OWNER $f impossible (lancer avec sudo)"
    chmod 0400 "$f" 2>/dev/null || bad "chmod 0400 $f impossible"
  fi
  uid="$(stat -c '%u' "$f")"; mode="$(stat -c '%a' "$f")"; size="$(stat -c '%s' "$f")"
  [ "$uid" = "$OWNER" ] || bad "$f : proprietaire uid $uid, attendu $OWNER (le conteneur ne pourrait pas le lire) -> sudo chown $OWNER:$OWNER $f"
  case "$mode" in 400|600) ;; *) bad "$f : mode $mode, attendu 400 (ou 600) : tout droit pour le groupe/les autres est refuse par le serveur -> chmod 0400 $f" ;; esac
  [ "$size" -gt 0 ] || bad "$f est vide"
  [ "$size" -le 65536 ] || bad "$f depasse 64 Kio"
  [ "$ERR" = 0 ] && : # (message de succes global en fin de script)
done

if [ "$CHILD" = 1 ]; then
  k="${ROOT_LINK_KEY_FILE:-}"
  if [ -z "$k" ]; then bad "ROOT_LINK_KEY_FILE non defini (cle publique racine de l'ancre)"
  elif [ -L "$k" ] || [ ! -f "$k" ]; then bad "$k : fichier regulier attendu (pas de lien symbolique)"
  else
    km="$(stat -c '%a' "$k")"; ku="$(stat -c '%u' "$k")"
    case "${km: -2:1}${km: -1}" in *[2367]*) bad "$k : mode $km inscriptible par le groupe/les autres (racine de confiance du sous-arbre) -> chmod 0644 $k" ;; esac
    [ "$ku" = "$OWNER" ] || case "${km: -1}" in 4|5|6|7) ;; *) bad "$k : illisible par l'UID $OWNER (mode $km, proprietaire $ku) -> chmod 0644 $k" ;; esac
  fi
fi

if [ "$ERR" = 0 ]; then echo "preflight secrets OK (${SECRETS[*]} dans $DIR)"; exit 0; fi
echo "preflight secrets : ECHEC (aucun 'docker compose up' avant correction ; 'sudo $0 --fix' corrige proprietaire et mode des fichiers presents)" >&2
exit 1
