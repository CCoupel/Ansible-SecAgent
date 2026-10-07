#!/usr/bin/env python3
"""Qualification d'un STOCKAGE PARTAGE pour STATE_DIR : « stockage non teste = non supporte ».

A lancer sur AU MOINS DEUX HOTES qui montent le MEME partage, avec le meme --dir, --hosts et --start-at
(epoch UTC, quelques dizaines de secondes dans le futur ; les horloges des hotes doivent etre synchronisees) :

  hote1$ T=$(( $(date +%s) + 60 )); echo $T
  hote1$ ./test_shared_storage.py run --dir /mnt/secagent-state/.storage-test --host h1 --hosts h1,h2 --start-at $T
  hote2$ ./test_shared_storage.py run --dir /mnt/secagent-state/.storage-test --host h2 --hosts h1,h2 --start-at $T
  (apres la fin des deux)
  hote1$ ./test_shared_storage.py verify --dir /mnt/secagent-state/.storage-test --hosts h1,h2

Verifie :
  1. O_EXCL   : pour chacun des N fichiers, EXACTEMENT un hote reussit open(O_CREAT|O_EXCL) ;
  2. rename   : un lecteur ne voit jamais de fichier partiel pendant que l'autre hote remplace un fichier
                par rename() (contenu autoportant : longueur + SHA-256) ;
  3. fsync    : fsync du fichier et du repertoire sans erreur, et contenu relu depuis l'autre hote apres rename.
Le test de coupure (kill -9 / coupure reseau pendant une ecriture) reste MANUEL : voir README.
Exit 0 = conforme ; 1 = NON CONFORME (stockage non supporte) ; 2 = usage.
"""
import argparse, hashlib, json, os, re, sys, time

HOST_RE = re.compile(r'[A-Za-z0-9._-]{1,64}')


def valid_host(h):
    """Liste blanche : le nom d'hote entre dans des noms de fichiers (jamais de separateur de chemin)."""
    return bool(HOST_RE.fullmatch(h)) and h not in ('.', '..')


N_EXCL = 500
N_RENAME = 300


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def wait_until(t):
    while time.time() < t:
        time.sleep(0.001)


def payload(host, seq):
    body = (f"{host}:{seq}:" + "x" * (4096 + seq % 2048)).encode()
    return hashlib.sha256(body).hexdigest().encode() + b"\n" + body


def valid(data):
    h, _, body = data.partition(b"\n")
    return hashlib.sha256(body).hexdigest().encode() == h and len(body) > 0


def run(a):
    d = a.dir
    os.makedirs(d, exist_ok=True)
    wait_until(a.start_at)
    wins = []
    for i in range(N_EXCL):  # 1. O_EXCL en course
        p = os.path.join(d, f"excl.{i}")
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        os.write(fd, a.host.encode())
        os.fsync(fd)
        os.close(fd)
        wins.append(i)
    fsync_dir(d)
    json.dump({"wins": wins}, open(os.path.join(d, f"result.excl.{a.host}.json"), "w"))
    # 2./3. rename atomique : le 1er hote ecrit, les autres lisent en continu.
    target = os.path.join(d, "atomic.dat")
    writer = a.host == a.hosts.split(",")[0]
    wait_until(a.start_at + 5)
    bad = reads = 0
    if writer:
        for seq in range(N_RENAME):
            tmp = os.path.join(d, f"atomic.{a.host}.tmp")
            fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            os.write(fd, payload(a.host, seq))
            os.fsync(fd)           # 3. fsync fichier
            os.close(fd)
            os.rename(tmp, target)
            fsync_dir(d)           # 3. fsync repertoire
            time.sleep(0.005)
    else:
        end = time.time() + 5 + N_RENAME * 0.02
        while time.time() < end:
            try:
                data = open(target, "rb").read()
            except FileNotFoundError:
                continue
            reads += 1
            if not valid(data):
                bad += 1
    json.dump({"reads": reads, "partial": bad}, open(os.path.join(d, f"result.rename.{a.host}.json"), "w"))
    print(f"{a.host}: {len(wins)} fichiers O_EXCL gagnes, {reads} lectures, {bad} partielles")
    return 0


def verify(a):
    d, hosts, fail = a.dir, a.hosts.split(","), False
    res = {h: set(json.load(open(os.path.join(d, f"result.excl.{h}.json")))["wins"]) for h in hosts}
    for i in range(N_EXCL):
        winners = [h for h in hosts if i in res[h]]
        if len(winners) != 1:
            print(f"ECHEC O_EXCL : excl.{i} a {len(winners)} gagnant(s) {winners}")
            fail = True
    for h in hosts:
        r = json.load(open(os.path.join(d, f"result.rename.{h}.json")))
        if r["partial"]:
            print(f"ECHEC rename : {h} a lu {r['partial']} fichier(s) partiel(s)")
            fail = True
    readers = [json.load(open(os.path.join(d, f"result.rename.{h}.json")))["reads"] for h in hosts[1:]]
    if readers and not any(readers):
        print("ECHEC rename : aucun lecteur n'a pu lire atomic.dat (test non significatif)")
        fail = True
    print("RESULTAT : " + ("NON CONFORME — stockage NON SUPPORTE" if fail else "CONFORME (O_EXCL, rename, fsync) ; test de coupure manuel a faire"))
    return 1 if fail else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("run", "verify"):
        s = sub.add_parser(n)
        s.add_argument("--dir", required=True)
        s.add_argument("--hosts", required=True, help="liste h1,h2 (le premier ecrit pour le test rename)")
        if n == "run":
            s.add_argument("--host", required=True)
            s.add_argument("--start-at", type=float, required=True)
    args = ap.parse_args()
    names = args.hosts.split(",") + ([args.host] if args.cmd == "run" else [])
    if not all(valid_host(n) for n in names):
        print("nom d'hote invalide (attendu [A-Za-z0-9._-]{1,64}, sans separateur)", file=sys.stderr)
        sys.exit(2)
    if args.cmd == "run" and args.host not in args.hosts.split(","):
        sys.exit(2)
    sys.exit(run(args) if args.cmd == "run" else verify(args))
