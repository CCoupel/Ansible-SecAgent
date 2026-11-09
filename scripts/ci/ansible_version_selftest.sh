#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

# Auto-test de la garde de version ansible-core de DEPLOYMENT/qualif/chain-test.sh (#249), avec un faux `ansible` :
# sans docker ni reseau ni ansible reel. Contrat : require_ansible_version compare STRICTEMENT la version de
# `${ANSIBLE_BIN:-ansible} --version` (`ansible [core X.Y.Z]`) a celle epinglee dans .github/ci/requirements-ansible.txt
# (`ansible-core==X.Y.Z`) ; en cas d'ecart ou de binaire absent : refus (code != 0), message citant version trouvee,
# version attendue et la commande de venv ; version egale => rc 0.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/priv"
bad=0
ko() { echo "KO  $*"; bad=1; }
ok() { echo "ok  $*"; }

PINNED="$(sed -n 's/^ansible-core==\([0-9][0-9.]*\).*/\1/p' "$ROOT/.github/ci/requirements-ansible.txt" | head -n1)"
[ -n "$PINNED" ] || { echo "KO  version epinglee introuvable dans requirements-ansible.txt"; exit 1; }
# Une version differente de l'epinglee, dans la meme serie majeure puis une serie plus ancienne (2.17 : FAILED rc=-1).
OTHER="2.17.9"; [ "$PINNED" != "$OTHER" ] || OTHER="2.18.1"
PATCH="${PINNED%.*}.$(( ${PINNED##*.} + 1 ))"   # ecart de patch seul : refus aussi (comparaison stricte)

stub() { # $1 nom du binaire, $2 version affichee
  cat > "$T/bin/$1" <<STUB
#!/usr/bin/env bash
echo "ansible [core $2]"
echo "  config file = None"
echo "  python version = 3.12.0"
STUB
  chmod +x "$T/bin/$1"
}

# guard <ANSIBLE_BIN> : joue require_ansible_version ; sortie combinee dans \$out, code dans \$rc
guard() {
  set +e
  out="$(env -u ANSIBLE_BIN SECAGENT_PRIVATE_DIR="$T/priv" ANSIBLE_BIN="$1" PATH="$T/bin:$PATH" bash -c '
    set -euo pipefail
    docker() { echo "docker-appele $*" >&2; return 1; }
    source "'"$ROOT"'/DEPLOYMENT/qualif/chain-test.sh"
    require_ansible_version
    echo "GARDE-PASSEE"
  ' 2>&1)"; rc=$?
  set -e
}

# 1. version egale a l'epinglee => OK
stub ansible-ok "$PINNED"
guard "$T/bin/ansible-ok"
{ [ "$rc" -eq 0 ] && case "$out" in *GARDE-PASSEE*) true ;; *) false ;; esac; } \
  && ok "version egale ($PINNED) : acceptee" || ko "version egale refusee (rc=$rc) : $out"

# 2. version differente => refus avec trouvee / attendue / commande venv
stub ansible-old "$OTHER"
guard "$T/bin/ansible-old"
[ "$rc" -ne 0 ] && ok "version $OTHER : code != 0" || ko "version $OTHER acceptee"
case "$out" in *GARDE-PASSEE*) ko "version $OTHER : l'execution a continue apres la garde" ;; *) ok "version $OTHER : execution interrompue" ;; esac
case "$out" in *"$OTHER"*) ok "refus : version trouvee ($OTHER) citee" ;; *) ko "refus : version trouvee absente : $out" ;; esac
case "$out" in *"$PINNED"*) ok "refus : version attendue ($PINNED) citee" ;; *) ko "refus : version attendue absente : $out" ;; esac
case "$out" in *"python3 -m venv"*"requirements-ansible.txt"*) ok "refus : commande venv indiquee" ;; *) ko "refus : commande venv absente : $out" ;; esac

# 3. comparaison stricte : un ecart de patch seul est refuse
stub ansible-patch "$PATCH"
guard "$T/bin/ansible-patch"
[ "$rc" -ne 0 ] && ok "ecart de patch ($PATCH) : refuse (comparaison stricte)" || ko "ecart de patch ($PATCH) accepte"

# 4. binaire absent => refus, sans traceback ni appel docker
guard "$T/bin/ansible-absent"
[ "$rc" -ne 0 ] && ok "binaire absent : code != 0" || ko "binaire absent accepte"
case "$out" in *GARDE-PASSEE*) ko "binaire absent : l'execution a continue" ;; *) ok "binaire absent : execution interrompue" ;; esac
case "$out" in *"python3 -m venv"*) ok "binaire absent : commande venv indiquee" ;; *) ko "binaire absent : commande venv absente : $out" ;; esac

# 5. sortie illisible (pas de `ansible [core X.Y.Z]`) => refus, jamais accepte par defaut
cat > "$T/bin/ansible-bizarre" <<'STUB'
#!/usr/bin/env bash
echo "quelque chose d'inattendu"
STUB
chmod +x "$T/bin/ansible-bizarre"
guard "$T/bin/ansible-bizarre"
[ "$rc" -ne 0 ] && ok "sortie illisible : refusee (fail-closed)" || ko "sortie illisible acceptee"

# 6. le controle ne depend pas d'un `ansible` du PATH quand ANSIBLE_BIN est fourni
stub ansible "$OTHER"
guard "$T/bin/ansible-ok"
[ "$rc" -eq 0 ] && ok "ANSIBLE_BIN prime sur l'ansible du PATH" || ko "ANSIBLE_BIN ignore (rc=$rc) : $out"

# 7. la garde est appelee par les points d'entree (smoke, failover) et par admission-503.sh
for f in DEPLOYMENT/qualif/chain-test.sh DEPLOYMENT/qualif/admission-503.sh; do
  grep -q 'require_ansible_version' "$ROOT/$f" && ok "$f appelle require_ansible_version" || ko "$f n'appelle pas require_ansible_version"
done
exit "$bad"
