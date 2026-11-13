#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Controle des SOURCES Compose avant podman-compose (#267, LOT-4, T48 2026-11-13).

podman-compose 1.5 fusionne les fichiers -f par `rec_merge_one` : une meme cle presente des deux cotes avec des TYPES
differents est refusee (« can't merge value of [child_state] of type NoneType and dict »), alors que docker compose
l'accepte. Ce script :
  1. refuse toute ressource de premier niveau (volumes, networks, secrets, configs) declaree avec une valeur NULLE
     (`nom:` sans valeur) : ecrire `nom: {}` ;
  2. reproduit la fusion de podman-compose sur une combinaison de fichiers, dans SON ordre (-f, puis les `include:`
     ajoutes a la fin), et refuse tout conflit de types ;
  3. refuse toute valeur qu'un fichier INCLUS ecraserait sur une surcharge -f (podman-compose fusionne les inclus en
     dernier, docker compose non) : cas T48 de `external` / `name` d'un volume ;
  4. refuse une combinaison ou un service porte `userns_mode` sans `x-podman: {in_pod: false}` : podman-compose 1.5
     place sinon le service dans `pod_<projet>` (--pod) et podman refuse « --userns and --pod cannot be set together »
     (T48, 2026-11-13) ;
  5. refuse un tmpfs a options `uid=` / `gid=` (podman 5.7 : « unknown mount option "uid=10001" », T48), apres
     interpolation des variables par l'environnement (sous Podman : SECAGENT_TMPFS_OPTS=U, release.env et chain-test.sh) ;
  6. refuse un `!override` d'un fichier -f sur une cle qu'un fichier inclus definit aussi : podman-compose le fusionne
     AVANT l'inclus, l'etiquette est perdue et la liste concatenee (tmpfs de a/b, T48). Une liste simple (ajout, ex.
     volumes de docker-compose.hooks.yml) reste permise : elle s'ajoute comme sous docker compose.
Les etiquettes `!override` / `!reset` (podman-compose >= 1.1, docker compose) sont lues avec leur effet sur la fusion.
Usage :
  check_compose_merge.py --no-null <fichier.yml>...        regle 1 sur chaque fichier
  check_compose_merge.py -f a.yml -f b.yml [-f c.yml]...    regle 2 sur la combinaison (et regle 1 sur ses fichiers)
Code 0 = conforme, 1 = non conforme, 2 = usage."""
import copy, os, re, sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML requis (python3-yaml)", file=sys.stderr)
    sys.exit(2)

RESOURCES = ("volumes", "networks", "secrets", "configs")


class MergeError(ValueError):
    pass


class Override:
    """Valeur etiquetee `!override` : remplace la valeur fusionnee au lieu de s'y ajouter (listes) ou d'y etre fusionnee."""
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Override) and other.value == self.value

    def __repr__(self):
        return f"!override {self.value!r}"


class Reset:
    """Valeur etiquetee `!reset` : retire la cle de la valeur fusionnee."""
    def __eq__(self, other):
        return isinstance(other, Reset)

    def __repr__(self):
        return "!reset"


class Loader(yaml.SafeLoader):
    pass


def _override(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return Override(loader.construct_sequence(node, deep=True))
    if isinstance(node, yaml.MappingNode):
        return Override(loader.construct_mapping(node, deep=True))
    return Override(loader.construct_scalar(node))


Loader.add_constructor("!override", _override)
Loader.add_constructor("!reset", lambda loader, node: Reset())


def plain(v):
    """Valeur sans etiquette (resultat de la fusion)."""
    if isinstance(v, Override):
        return plain(v.value)
    if isinstance(v, dict):
        return {k: plain(x) for k, x in v.items() if not isinstance(x, Reset)}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=Loader) or {}  # noqa: S506 - SafeLoader + deux etiquettes Compose


def null_resources(doc, name):
    errs = []
    for sec in RESOURCES:
        for key, val in (doc.get(sec) or {}).items():
            if val is None:
                errs.append(f"{name} : {sec}.{key} declare sans valeur (nul) : ecrire `{key}: {{}}` (podman-compose 1.5)")
    return errs


def rec_merge_one(target, source, path=""):
    """Meme regle que podman_compose.rec_merge_one (1.5) : type identique exige quand la cle existe des deux cotes."""
    for key, value2 in source.items():
        where = f"{path}.{key}" if path else key
        if isinstance(value2, Reset):
            target.pop(key, None)
            continue
        if isinstance(value2, Override):
            target[key] = plain(value2)
            continue
        if key not in target:
            target[key] = plain(value2)
            continue
        value = target[key]
        if key in ("command", "entrypoint"):
            target[key] = value2
            continue
        if not isinstance(value2, type(value)):
            raise MergeError(f"can't merge value of [{where}] of type {type(value).__name__} and {type(value2).__name__}")
        if isinstance(value2, list):
            value.extend(value2)
        elif isinstance(value2, dict):
            rec_merge_one(value, value2, where)
        else:
            target[key] = value2
    return target


def include_paths(doc, base):
    out = []
    for inc in doc.get("include") or []:
        p = inc if isinstance(inc, str) else (inc.get("path") if isinstance(inc, dict) else None)
        if isinstance(p, list):
            p = p[0] if p else None
        if p:
            out.append(os.path.join(os.path.dirname(base), p))
    return out


def expand(files):
    """Ordre REEL de podman-compose 1.5 (podman_compose.py:2289-2292) : les fichiers -f dans l'ordre, puis les fichiers
    `include:` AJOUTES A LA FIN de la liste (un fichier inclus est donc fusionne APRES toutes les surcharges -f, a
    l'inverse de docker compose). Retourne [(nom, document, inclus?)]."""
    queue = [(f, False) for f in files]
    out, i = [], 0
    while i < len(queue):
        f, inc = queue[i]
        doc = load(f)
        out.append((f, doc, inc))
        queue.extend((p, True) for p in include_paths(doc, f))
        i += 1
    return out


def leaves(doc, path=()):
    """Valeurs scalaires (et dicts vides) par chemin ; les listes sont concatenees par podman-compose : ignorees."""
    if isinstance(doc, (Override, Reset)):
        yield path, doc
        return
    if isinstance(doc, dict):
        if not doc and path:
            return
        for k, v in doc.items():
            yield from leaves(v, path + (str(k),))
    elif not isinstance(doc, list):
        yield path, doc


def include_overrides(order):
    """Valeurs qu'un fichier INCLUS ecraserait sous podman-compose (fusionne en dernier) alors qu'un fichier -f les fixe
    autrement : docker compose garderait la surcharge, podman-compose la valeur incluse (cas T48 : secagent_secrets
    `external: false` de la surcharge Podman ecrase par `external: true` de docker-compose.server.yml)."""
    over = {}
    for name, doc, inc in order:
        if not inc:
            for p, v in leaves({k: v for k, v in doc.items() if k != "include"}):
                over[p] = (name, v)
    errs = []
    for name, doc, inc in order:
        if not inc:
            continue
        for p, v in leaves({k: v for k, v in doc.items() if k != "include"}):
            if p in over and over[p][1] != v:
                errs.append(f"{'.'.join(p)} : {over[p][0]} fixe {over[p][1]!r} mais {name} (include:, fusionne EN DERNIER par "
                            f"podman-compose 1.5) impose {v!r} : la surcharge serait ignoree sous Podman")
    return errs


FALSY = ("false", "0", "no", "off", "n", "f")


def userns_without_podless(merged):
    """Regle 4 : meme lecture que PodmanCompose.resolve_pod_name (1.5) : x-podman.in_pod, vrai par defaut."""
    users = sorted(n for n, s in (merged.get("services") or {}).items() if isinstance(s, dict) and s.get("userns_mode"))
    in_pod = (merged.get("x-podman") or {}).get("in_pod", True)
    podless = in_pod is False or (isinstance(in_pod, str) and in_pod.strip().lower() in FALSY)
    if users and not podless:
        return [f"services {', '.join(users)} : userns_mode sans `x-podman: {{in_pod: false}}` : podman-compose 1.5 les "
                f"place dans pod_<projet> et podman refuse « --userns and --pod cannot be set together »"]
    return []


def interp(text):
    """Interpolation Compose minimale (${VAR}, ${VAR:-defaut}, ${VAR-defaut}, ${VAR:?msg}) par os.environ."""
    def sub(m):
        name, op, arg = m.group(1), m.group(2) or "", m.group(3) or ""
        val = os.environ.get(name)
        if op in (":-", ":?") and not val:
            return arg if op == ":-" else ""
        if op == "-" and val is None:
            return arg
        return val or ""
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|:\?|-)([^}]*))?\}", sub, text)


def tmpfs_uid_options(merged):
    """Regle 5 : options tmpfs uid=/gid= refusees par podman (le rendu docker compose les accepte)."""
    errs = []
    for name, svc in sorted((merged.get("services") or {}).items()):
        for t in (svc or {}).get("tmpfs") or [] if isinstance(svc, dict) else []:
            t = interp(str(t))
            opts = t.split(":", 1)[1].split(",") if ":" in t else []
            bad = [o for o in opts if o.split("=", 1)[0] in ("uid", "gid")]
            if bad:
                errs.append(f"services.{name}.tmpfs '{t}' : options {','.join(bad)} refusees par podman (« unknown mount "
                            f"option ») : sous Podman, SECAGENT_TMPFS_OPTS=U (release.env, chain-test.sh)")
    return errs


def overrides(doc, path=()):
    """Chemins des valeurs `!override` d'un document."""
    if isinstance(doc, Override):
        yield path
    elif isinstance(doc, dict):
        for k, v in doc.items():
            yield from overrides(v, path + (str(k),))


def list_paths(doc, path=()):
    if isinstance(doc, list):
        yield path
    elif isinstance(doc, dict):
        for k, v in doc.items():
            yield from list_paths(v, path + (str(k),))


def include_list_overrides(order):
    """Regle 6 : !override d'un -f sur une cle aussi definie par un fichier inclus (fusionne APRES)."""
    inc_paths = set()
    for name, doc, inc in order:
        if inc:
            body = plain({k: v for k, v in doc.items() if k != "include"})
            inc_paths |= {p for p, _v in leaves(body)} | set(list_paths(body))
    errs = []
    for name, doc, inc in order:
        if inc:
            continue
        for p in overrides({k: v for k, v in doc.items() if k != "include"}):
            if p in inc_paths:
                errs.append(f"{'.'.join(p)} : !override de {name} sur une cle d'un fichier inclus : podman-compose 1.5 "
                            f"fusionne l'inclus EN DERNIER (!override perdu, liste concatenee) : passer par une variable")
    return errs


def check_merge(files):
    errs, merged = [], {}
    order = expand(files)
    for name, doc, _inc in order:
        errs += null_resources(doc, name)
        body = copy.deepcopy({k: v for k, v in doc.items() if k != "include"})   # la fusion mute ses entrees
        try:
            rec_merge_one(merged, body)
        except MergeError as e:
            errs.append(f"{' + '.join(files)} : {e} (en fusionnant {name})")
    errs += include_overrides(order)
    errs += userns_without_podless(merged)
    errs += tmpfs_uid_options(merged)
    errs += include_list_overrides(order)
    return errs


def main(argv):
    args = argv[1:]
    errs = []
    if args[:1] == ["--no-null"] and len(args) > 1:
        for f in args[1:]:
            errs += null_resources(load(f), f)
        label = f"{len(args) - 1} fichier(s)"
    elif args and len(args) % 2 == 0 and all(a == "-f" for a in args[0::2]):
        files = args[1::2]
        errs = check_merge(files)
        label = " + ".join(files)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for e in errs:
        print(f"::error::{e}")
    if not errs:
        print(f"OK fusion podman-compose : {label}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
