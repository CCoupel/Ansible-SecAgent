"""
facts_collector.py — Collecte des informations système pour l'enrollment AnsibleRelay.

Les facts collectés sont envoyés au serveur lors du POST /api/register et
alimentent l'inventaire dynamique Ansible.

Scope MVP : Linux uniquement.
Aucune dépendance externe : Python stdlib uniquement (subprocess, /proc, sysfs).
"""

import os
import platform
import re
import shutil
import socket
import subprocess
from typing import Any


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

def _read_file(path: str) -> str:
    """Lit un fichier texte et retourne son contenu, ou '' en cas d'erreur."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _run(cmd: list[str]) -> str:
    """Exécute une commande et retourne stdout, ou '' en cas d'erreur."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.stdout.decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------------------
# Collecte individuelle — chaque fonction est indépendante (graceful degradation)
# ---------------------------------------------------------------------------

def _get_hostname() -> str:
    """Retourne le nom d'hôte court de la machine."""
    return socket.gethostname()


def _get_non_loopback_ips() -> list[str]:
    """Retourne la liste des adresses IP non-loopback de la machine.

    Utilise socket.getaddrinfo sur le hostname de la machine pour obtenir
    les adresses IP associées. Filtre les adresses de loopback (127.x.x.x
    et ::1).

    Returns:
        Liste des adresses IP (IPv4 et IPv6) non-loopback, sans doublons,
        triées pour une sortie déterministe.
    """
    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        # getaddrinfo retourne (family, type, proto, canonname, sockaddr)
        # sockaddr est (address, port) pour IPv4 ou (address, port, flow, scope) pour IPv6
        results = socket.getaddrinfo(hostname, None)
        seen: set[str] = set()
        for _family, _type, _proto, _canonname, sockaddr in results:
            addr = sockaddr[0]
            if addr in seen:
                continue
            seen.add(addr)
            # Filtre loopback IPv4 et IPv6
            if addr.startswith("127.") or addr == "::1":
                continue
            ips.append(addr)
    except OSError:
        # En cas d'échec de résolution, retourne une liste vide plutôt que de crasher
        pass
    return sorted(ips)


def _get_os_family() -> str:
    """Retourne la famille d'OS (ex: 'Debian', 'RedHat', 'Arch', 'Linux').

    Lit /etc/os-release pour identifier la distribution.
    Retourne 'Linux' si la famille ne peut pas être déterminée.
    """
    os_release = _read_file("/etc/os-release")
    if not os_release:
        return platform.system() or "Unknown"

    id_like = ""
    distro_id = ""
    for line in os_release.splitlines():
        if line.startswith("ID_LIKE="):
            id_like = line.split("=", 1)[1].strip().strip('"').lower()
        elif line.startswith("ID="):
            distro_id = line.split("=", 1)[1].strip().strip('"').lower()

    # Priorité à ID_LIKE pour regrouper les distributions
    for token in (id_like + " " + distro_id).split():
        if token in ("debian", "ubuntu"):
            return "Debian"
        if token in ("rhel", "fedora", "centos", "rocky", "almalinux"):
            return "RedHat"
        if token in ("suse", "opensuse"):
            return "Suse"
        if token == "arch":
            return "Arch"
        if token in ("alpine",):
            return "Alpine"
        if token in ("gentoo",):
            return "Gentoo"

    return "Linux"


def _get_kernel_version() -> str:
    """Retourne la version du noyau Linux (ex: '5.15.0-91-generic').

    Utilise platform.release() qui lit uname(2).
    """
    return platform.release()


def _get_cpu_count() -> int:
    """Retourne le nombre de CPUs logiques.

    Lit /proc/cpuinfo (nombre de lignes 'processor :').
    Repli sur os.cpu_count() si /proc/cpuinfo n'est pas disponible.
    """
    cpuinfo = _read_file("/proc/cpuinfo")
    if cpuinfo:
        count = cpuinfo.count("\nprocessor\t:")
        # Compte aussi la première occurrence sans saut de ligne précédent
        if cpuinfo.startswith("processor\t:"):
            count += 1
        if count > 0:
            return count

    fallback = os.cpu_count()
    return fallback if fallback is not None else 0


def _get_memory_total_mb() -> int:
    """Retourne la mémoire RAM totale en mégaoctets.

    Lit /proc/meminfo, ligne 'MemTotal:'.
    Retourne 0 si indisponible.
    """
    meminfo = _read_file("/proc/meminfo")
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            # Ligne typique : "MemTotal:       16384000 kB"
            parts = line.split()
            if len(parts) >= 2:
                try:
                    kb = int(parts[1])
                    return kb // 1024
                except ValueError:
                    pass
    return 0


def _get_disk_total_gb() -> float:
    """Retourne la capacité totale du système de fichiers racine en Go.

    Utilise shutil.disk_usage() — cross-platform (Linux, macOS, Windows).
    Sur Linux/macOS utilise '/', sur Windows utilise 'C:\\' si '/' échoue.
    Retourne 0.0 si indisponible.
    """
    for path in ("/", "C:\\"):
        try:
            usage = shutil.disk_usage(path)
            return round(usage.total / (1024 ** 3), 2)
        except OSError:
            continue
    return 0.0


def _get_network_interfaces() -> list[dict[str, Any]]:
    """Retourne la liste des interfaces réseau avec leurs adresses IP.

    Lit /sys/class/net/ pour lister les interfaces, puis interroge
    /proc/net/if_inet6 et /proc/net/fib_trie (ou 'ip addr' en repli)
    pour les adresses IPv4/IPv6.

    Chaque entrée du dict contient :
        - ``name`` (str)  : nom de l'interface (ex: 'eth0')
        - ``ipv4`` (list[str]) : adresses IPv4 (sans masque)
        - ``ipv6`` (list[str]) : adresses IPv6 (sans préfixe)
        - ``mac``  (str)  : adresse MAC ou '' si indisponible

    Les interfaces de loopback (lo) sont exclues.
    """
    interfaces: list[dict[str, Any]] = []

    # Lister les interfaces depuis sysfs
    net_dir = "/sys/class/net"
    try:
        iface_names = sorted(os.listdir(net_dir))
    except OSError:
        # Repli : utiliser 'ip link' si sysfs non disponible
        output = _run(["ip", "link", "show"])
        iface_names = re.findall(r"^\d+:\s+(\S+):", output, re.MULTILINE)

    for name in iface_names:
        # Exclure loopback
        if name == "lo":
            continue

        # Adresse MAC
        mac = _read_file(f"/sys/class/net/{name}/address").strip()

        # Adresses IPv4 via /proc/net/fib_trie (uniquement adresses locales)
        ipv4_addrs = _collect_ipv4_for_iface(name)

        # Adresses IPv6 via /proc/net/if_inet6
        ipv6_addrs = _collect_ipv6_for_iface(name)

        interfaces.append({
            "name": name,
            "ipv4": ipv4_addrs,
            "ipv6": ipv6_addrs,
            "mac": mac,
        })

    return interfaces


def _collect_ipv4_for_iface(iface_name: str) -> list[str]:
    """Collecte les adresses IPv4 d'une interface en lisant /proc/net/fib_trie.

    Algorithme : dans fib_trie, les blocs 'LOCAL' sous une interface
    contiennent les adresses assignées. En pratique, on utilise 'ip addr'
    comme méthode principale car /proc/net/fib_trie est complexe à parser
    correctement sur toutes les distributions.

    Repli sur 'ip addr show <iface>' si disponible, sinon retourne [].
    """
    # Tentative via 'ip addr show' (outil universel sur Linux moderne)
    output = _run(["ip", "-4", "addr", "show", iface_name])
    addrs: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            # "inet 192.168.1.10/24 brd ..."
            parts = line.split()
            if len(parts) >= 2:
                # Retire le préfixe CIDR
                addr = parts[1].split("/")[0]
                if addr and not addr.startswith("127."):
                    addrs.append(addr)
    return addrs


def _collect_ipv6_for_iface(iface_name: str) -> list[str]:
    """Collecte les adresses IPv6 d'une interface en lisant /proc/net/if_inet6.

    Format /proc/net/if_inet6 :
        <addr_hex32> <ifindex> <prefix_len_hex> <scope_hex> <flags_hex> <name>

    Scope 0x10 = link-local, 0x00 = global.
    """
    addrs: list[str] = []
    if_inet6 = _read_file("/proc/net/if_inet6")
    if not if_inet6:
        # Repli sur 'ip addr show'
        output = _run(["ip", "-6", "addr", "show", iface_name])
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1].split("/")[0]
                    if addr and addr != "::1":
                        addrs.append(addr)
        return addrs

    for line in if_inet6.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        if parts[5] != iface_name:
            continue
        raw = parts[0]
        # Formate les 32 hex chars en adresse IPv6
        addr = ":".join(raw[i:i+4] for i in range(0, 32, 4))
        # Normalise via socket (gère les zéros consécutifs)
        try:
            addr = socket.inet_ntop(
                socket.AF_INET6,
                bytes.fromhex(raw)
            )
        except (ValueError, OSError):
            pass
        if addr != "::1":
            addrs.append(addr)

    return addrs


def _get_installed_packages() -> dict[str, str]:
    """Retourne un échantillon des packages installés.

    Tente dpkg-query (Debian/Ubuntu), puis rpm (RedHat), puis apk (Alpine).
    Retourne un dict {nom: version} limité aux 200 premiers packages,
    ou un dict vide si aucun gestionnaire n'est disponible.

    La limite à 200 évite de surcharger le payload d'enrollment.
    """
    packages: dict[str, str] = {}

    # Debian / Ubuntu
    output = _run([
        "dpkg-query",
        "--show",
        "--showformat=${Package}\t${Version}\n",
    ])
    if output:
        for line in output.splitlines()[:200]:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                packages[parts[0]] = parts[1]
        return packages

    # RedHat / CentOS / Fedora
    output = _run([
        "rpm",
        "-qa",
        "--queryformat",
        "%{NAME}\t%{VERSION}-%{RELEASE}\n",
    ])
    if output:
        for line in output.splitlines()[:200]:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                packages[parts[0]] = parts[1]
        return packages

    # Alpine Linux
    output = _run(["apk", "info", "-v"])
    if output:
        for line in output.splitlines()[:200]:
            # "package-1.2.3-r0" → nom + version
            match = re.match(r"^(.+?)-(\d[^\s]*)$", line.strip())
            if match:
                packages[match.group(1)] = match.group(2)
        return packages

    return packages


# ---------------------------------------------------------------------------
# Fonction publique principale
# ---------------------------------------------------------------------------

def collect_facts() -> dict[str, Any]:
    """Collecte les informations système nécessaires à l'enrollment de l'agent.

    Cette fonction est pure : elle n'a pas d'effets de bord, ne modifie aucun
    état global et peut être appelée plusieurs fois sans conséquence.

    Graceful degradation : si une fact est indisponible, elle prend une valeur
    neutre (0, '', [], {}) sans lever d'exception.

    Les données collectées alimentent :
    - Le corps du POST /api/register (enrollment initial)
    - L'inventaire dynamique Ansible (hostvars)

    Returns:
        Dictionnaire avec les clés suivantes :

        - ``hostname`` (str) : Nom d'hôte court de la machine.
        - ``os`` (dict) : Informations système d'exploitation :
            - ``system`` (str) : Nom du système (ex: "Linux")
            - ``release`` (str) : Version du noyau (ex: "5.15.0-91-generic")
            - ``version`` (str) : Description détaillée de la version OS
        - ``os_family`` (str) : Famille de distribution (ex: 'Debian', 'RedHat').
        - ``kernel_version`` (str) : Version du noyau (ex: '5.15.0-91-generic').
        - ``cpu_count`` (int) : Nombre de CPUs logiques.
        - ``memory_total_mb`` (int) : Mémoire RAM totale en mégaoctets.
        - ``disk_total_gb`` (float) : Capacité totale du filesystem '/' en Go.
        - ``ip_addresses`` (list[str]) : Adresses IP non-loopback (IPv4 + IPv6).
        - ``network_interfaces`` (list[dict]) : Interfaces réseau avec IPs et MAC.
        - ``python_version`` (str) : Version Python courante (ex: '3.11.6').
        - ``packages`` (dict[str, str]) : Packages installés {nom: version} (max 200).

    Example::

        >>> facts = collect_facts()
        >>> facts["hostname"]
        'my-server'
        >>> facts["os_family"]
        'Debian'
        >>> facts["cpu_count"] > 0
        True
        >>> facts["memory_total_mb"] > 0
        True
        >>> facts["disk_total_gb"] > 0.0
        True
        >>> isinstance(facts["network_interfaces"], list)
        True
    """
    return {
        "hostname": _get_hostname(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
        },
        "os_family": _get_os_family(),
        "kernel_version": _get_kernel_version(),
        "cpu_count": _get_cpu_count(),
        "memory_total_mb": _get_memory_total_mb(),
        "disk_total_gb": _get_disk_total_gb(),
        "ip_addresses": _get_non_loopback_ips(),
        "network_interfaces": _get_network_interfaces(),
        "python_version": platform.python_version(),
        "packages": _get_installed_packages(),
    }
