#!/usr/bin/env python3
"""Garde des workflows et actions GitHub (#227 / LOT-2.2, point ouvert de #224, M6 de la revue securite).

Usage : check_actions_pinned.py [fichier ...]   (code 0 = OK, 1 = au moins une erreur, toutes listees)
  Sans argument : .github/workflows/*.yml et *.yaml, .github/actions/**/action.yml|yaml, action.yml|yaml (racine),
  depuis la racine du depot.

Chaque fichier est CHARGE EN YAML (yaml.safe_load) puis parcouru en entier (jobs, steps, actions composites
`runs.steps`, workflows reutilisables `jobs.<id>.uses`, `container`, `services`) : toute ecriture YAML valide est vue
(`uses :`, valeur a la ligne, cle entre guillemets, mapping de flux, scalaires multi-lignes ou entre guillemets).

Echec si :
  - une valeur `uses` n'est pas `<owner>/<repo>[/<chemin>]@<SHA 40 hex>` suivie, dans le texte, d'un commentaire
    `# vX.Y.Z` ; ou contient une expression ${{ }} (cible non verifiable). Exceptions : `./...` (action ou workflow
    local, lui-meme analyse s'il est passe a la garde) ; `docker://<image>@sha256:<64 hex>` ;
  - une valeur `run` (chaine, quelle que soit sa forme) ou le `with.script` d'actions/github-script contient ${{ }} :
    Actions l'interpole AVANT l'interpreteur (injection) ; les valeurs passent par `env:` ;
  - l'image d'un `container` ou d'un `services.<nom>` n'est pas epinglee par digest @sha256:<64 hex>, ou contient ${{ }} ;
  - le fichier n'est pas un document YAML de type mapping.
Limite connue (B23) : la garde ne verifie pas que le SHA correspond au tag du commentaire (revue + Dependabot).

PyYAML : en CI, installe dans un venv jetable depuis .github/ci/requirements-guard.txt (version et sommes epinglees,
--require-hashes) ; il n'est pas suppose present sur le runner.
"""
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - message explicite plutot qu'une trace
    print("::error::PyYAML introuvable : pip install --require-hashes -r .github/ci/requirements-guard.txt")
    sys.exit(2)

PINNED_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
GITHUB_SCRIPT_RE = re.compile(r"^actions/github-script@", re.I)
EXPR = "${{"


REF_RE = re.compile(r"""(?<![\w./-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s'"]+)?@[0-9a-f]{40})(?![0-9a-f])""")
COMMENT_AFTER_RE = re.compile(r"""^['"]?\s*[,}\]]?\s*#\s*v\d+\.\d+\.\d+(?:\s|$)""")


def _comment_errors(text: str, name: str) -> list:
    """Chaque ligne qui porte une reference epinglee `owner/repo@<SHA>` la fait suivre d'un commentaire `# vX.Y.Z`
    (passe texte : les commentaires YAML ne sont pas visibles apres chargement). Ligne par ligne : une action epinglee
    deux fois ne peut pas emprunter le commentaire de l'autre occurrence."""
    errs = []
    for n, line in enumerate(text.splitlines(), 1):
        for m in REF_RE.finditer(line):
            if not COMMENT_AFTER_RE.match(line[m.end():]):
                errs.append(f"{name}:{n}: action {m.group(1).split('@')[0]!r} sans commentaire de version `# vX.Y.Z` sur sa ligne")
    return errs


def _check_uses(value, where: str, text: str, errs: list) -> None:
    if not isinstance(value, str):
        errs.append(f"{where}: uses doit etre une chaine")
        return
    v = value.strip()
    if EXPR in v:
        errs.append(f"{where}: uses contient une expression ${{{{ }}}} (cible non verifiable)")
    elif v.startswith("./"):
        return
    elif v.startswith("docker://"):
        if not DOCKER_RE.match(v):
            errs.append(f"{where}: image {v!r} non epinglee par digest @sha256:<64 hex>")
    elif not PINNED_RE.match(v):
        errs.append(f"{where}: action {v!r} non epinglee par un SHA de 40 hex")


def _check_image(value, where: str, errs: list) -> None:
    image = value.get("image") if isinstance(value, dict) else value
    if image is None:
        return
    if not isinstance(image, str) or EXPR in image or not IMAGE_RE.match(image.strip()):
        errs.append(f"{where}: image {image!r} non epinglee par digest @sha256:<64 hex> (ou expression ${{{{ }}}})")


def _walk(node, path: str, text: str, errs: list) -> None:
    if isinstance(node, dict):
        uses = node.get("uses")
        if "uses" in node:
            _check_uses(uses, f"{path}.uses", text, errs)
        run = node.get("run")
        if isinstance(run, str) and EXPR in run:
            errs.append(f"{path}.run: expression ${{{{ }}}} dans un script run: (passer la valeur par env:)")
        if isinstance(uses, str) and GITHUB_SCRIPT_RE.match(uses.strip()):
            script = (node.get("with") or {}).get("script") if isinstance(node.get("with"), dict) else None
            if isinstance(script, str) and EXPR in script:
                errs.append(f"{path}.with.script: expression ${{{{ }}}} dans un script github-script (passer par env:)")
        if "container" in node and isinstance(node.get("container"), (str, dict)):
            _check_image(node["container"], f"{path}.container", errs)
        if isinstance(node.get("services"), dict):
            for name, svc in node["services"].items():
                _check_image(svc, f"{path}.services.{name}", errs)
        for k, v in node.items():
            _walk(v, f"{path}.{k}", text, errs)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", text, errs)


def check_text(text: str, name: str) -> list:
    """Erreurs (liste de chaines) pour le contenu `text` d'un workflow ou d'une action nommee `name`."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"{name}: YAML invalide ({str(e).splitlines()[0]})"]
    if not isinstance(doc, dict):
        return [f"{name}: document YAML attendu de type mapping"]
    errs: list = []
    _walk(doc, name, text, errs)
    return errs + _comment_errors(text, name)


def default_files(root: str = ".") -> list:
    pats = [".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/**/action.yml",
            ".github/actions/**/action.yaml", "action.yml", "action.yaml"]
    out = []
    for p in pats:
        out += sorted(glob.glob(os.path.join(root, p), recursive=True))
    return out


def main(argv) -> int:
    files = argv or default_files()
    if not files:
        print("::error::aucun workflow trouve (lancer depuis la racine du depot)")
        return 2
    errs = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            errs += check_text(fh.read(), path)
    for e in errs:
        print(f"::error::{e}")
    print("FAIL workflows" if errs else f"OK {len(files)} fichier(s) : actions et images epinglees, aucun ${{{{ }}}} dans run/script")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
