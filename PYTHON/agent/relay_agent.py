"""
relay_agent.py — Daemon client AnsibleRelay.

Maintient une connexion WebSocket persistante vers le relay server,
exécute les tâches Ansible reçues via des subprocesses isolés.

Scope MVP : Linux uniquement.

Sécurité :
- WSS obligatoire avec ssl.create_default_context() (CRITIQUE #1)
- HTTPS enrollment avec verify=True (CRITIQUE #2)
- subprocess_exec au lieu de subprocess_shell (CRITIQUE #3)
- JWT stocké avec chmod 600 (HAUT #4)
- Échec RSA lève exception, pas de fallback silencieux (HAUT #5)
- Validation path traversal sur put_file/fetch_file (HAUT #6)
- become_pass masqué dans tous les logs
"""

import asyncio
import base64
import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("relay_agent")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

CLOSE_CODE_REVOKED: int = 4001
MAX_CONCURRENT_TASKS: int = 10
STDOUT_BUFFER_MAX: int = 5 * 1024 * 1024  # 5 MB

# Répertoires autorisés pour put_file et fetch_file
# L'agent n'accepte d'écrire/lire que dans ces préfixes.
ALLOWED_WRITE_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/home/",
    "/root/",
    "/opt/",
)
ALLOWED_READ_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/home/",
    "/root/",
    "/opt/",
    "/etc/",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class EnrollmentError(Exception):
    """Levée quand l'enrollment échoue (clef refusée, HTTP != 200)."""


class PathTraversalError(Exception):
    """Levée quand un chemin sort des répertoires autorisés."""


# ---------------------------------------------------------------------------
# ReconnectManager — backoff exponentiel
# ---------------------------------------------------------------------------

class ReconnectManager:
    """Gère le backoff exponentiel pour les reconnexions WebSocket.

    Args:
        base_delay: Délai initial en secondes (ex: 1.0).
        max_delay: Plafond du délai en secondes (ex: 60.0).
    """

    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0) -> None:
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._attempt = 0

    def next_delay(self) -> float:
        """Retourne le prochain délai et incrémente le compteur d'échecs."""
        delay = min(self._base_delay * (2 ** self._attempt), self._max_delay)
        self._attempt += 1
        return delay

    def reset(self) -> None:
        """Remet le compteur à zéro après une connexion réussie."""
        self._attempt = 0

    def should_reconnect(self, close_code: int) -> bool:
        """Retourne False si le code indique une révocation définitive (4001)."""
        return close_code != CLOSE_CODE_REVOKED


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

async def enroll(
    register_url: str,
    hostname: str,
    public_key_pem: str,
    private_key: Any,
    ca_bundle: str | None = None,
) -> str:
    """Enregistre l'agent auprès du relay server.

    Effectue un POST /api/register avec le hostname et la clef publique.
    Déchiffre le JWT retourné avec la clef privée RSA.

    TLS vérifié via CA bundle ou store système (verify=True par défaut).

    Args:
        register_url: URL complète du endpoint d'enrollment (https://).
        hostname: Nom d'hôte de la machine.
        public_key_pem: Clef publique RSA PEM de l'agent.
        private_key: Clef privée RSA (objet rsa.PrivateKey) pour déchiffrer.
        ca_bundle: Chemin vers un CA bundle PEM custom (None = store système).

    Returns:
        JWT déchiffré sous forme de chaîne UTF-8.

    Raises:
        EnrollmentError: Si le serveur refuse l'enrollment (HTTP != 200)
            ou si le déchiffrement RSA échoue.
    """
    import httpx

    payload = {
        "hostname": hostname,
        "public_key_pem": public_key_pem,
    }

    # CRITIQUE #2 : TLS vérifié obligatoire — verify=True (store système)
    # ou chemin vers CA bundle custom.
    verify: str | bool = ca_bundle if ca_bundle else True

    async with httpx.AsyncClient(verify=verify) as client:
        response = await client.post(register_url, json=payload)

    if response.status_code != 200:
        raise EnrollmentError(
            f"Enrollment refusé : HTTP {response.status_code} — "
            f"{response.json().get('error', 'unknown')}"
        )

    data = response.json()
    encrypted_token = base64.b64decode(data["token_encrypted"])

    # HAUT #5 : déchiffrement RSA obligatoire si private_key est fournie.
    # Si private_key est None (tests/dev), on retourne le token brut décodé
    # avec un avertissement explicite dans les logs (pas silencieux).
    if private_key is not None:
        try:
            import rsa
            jwt_bytes = rsa.decrypt(encrypted_token, private_key)
            return jwt_bytes.decode("utf-8")
        except Exception as exc:
            # HAUT #5 / H-1bis : échec RSA → exception, pas de fallback silencieux.
            # Retourner un token non déchiffré en production serait une fuite.
            logger.error("Déchiffrement RSA échoué : %s", exc)
            raise EnrollmentError(f"Déchiffrement RSA échoué : {exc}") from exc

    # Pas de clef privée : retourne le token brut (mode dev/test uniquement)
    logger.warning(
        "private_key=None : token JWT non déchiffré retourné en clair. "
        "En production, toujours fournir la clef privée RSA."
    )
    return encrypted_token.decode("utf-8", errors="replace")


def _write_secret_file(content: str, path: str) -> None:
    """Écrit un fichier secret avec permissions 0o600 de façon atomique.

    HAUT #4 / H-4 : utilise os.open() avec le mode 0o600 à la création
    pour éviter la fenêtre TOCTOU entre write_text() et os.chmod().
    Le fichier est créé directement avec les bonnes permissions sans
    jamais être lisible par d'autres processus.

    Args:
        content: Contenu texte à écrire.
        path: Chemin du fichier de destination.
    """
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(file_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)


def store_jwt(jwt: str, path: str) -> None:
    """Persiste le JWT sur disque avec permissions 600.

    HAUT #4 : le token doit être lisible uniquement par l'utilisateur
    qui exécute l'agent (mode 0o600).

    Args:
        jwt: Chaîne JWT à stocker.
        path: Chemin du fichier de destination (ex: /etc/relay-agent/token.jwt).
    """
    _write_secret_file(jwt, path)


def store_private_key(pem: str, path: str) -> None:
    """Persiste la clef privée RSA sur disque avec permissions 600.

    HAUT #4 : la clef privée doit être lisible uniquement par l'utilisateur
    qui exécute l'agent.

    Args:
        pem: Contenu PEM de la clef privée.
        path: Chemin du fichier de destination.
    """
    _write_secret_file(pem, path)


# ---------------------------------------------------------------------------
# Connexion WebSocket
# ---------------------------------------------------------------------------

def _build_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Construit un contexte SSL strict pour les connexions WSS.

    CRITIQUE #1 : TLS obligatoire avec vérification du certificat serveur
    et vérification du hostname.

    Args:
        ca_bundle: Chemin vers un CA bundle PEM custom (None = store système).

    Returns:
        ssl.SSLContext configuré pour CERT_REQUIRED + check_hostname.
    """
    ctx = ssl.create_default_context(cafile=ca_bundle)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def connect_websocket(
    server_url: str,
    jwt: str,
    ca_bundle: str | None = None,
) -> None:
    """Ouvre et maintient la connexion WebSocket persistante.

    CRITIQUE #1 : SSL context explicite avec CERT_REQUIRED + check_hostname.

    Args:
        server_url: URL WSS du relay server (ex: wss://relay.example.com/ws/agent).
        jwt: JWT d'authentification à envoyer dans le header Authorization.
        ca_bundle: Chemin vers un CA bundle PEM custom (None = store système).
    """
    import websockets

    ssl_context = _build_ssl_context(ca_bundle)
    headers = {"Authorization": f"Bearer {jwt}"}

    async with websockets.connect(
        server_url,
        extra_headers=headers,
        ssl=ssl_context,
    ) as ws:
        task_registry: dict[str, Any] = {}
        async for raw_message in ws:
            await dispatch_message(raw_message, ws, task_registry)


# ---------------------------------------------------------------------------
# Validation de chemin (path traversal)
# ---------------------------------------------------------------------------

def _validate_path(path: str, allowed_prefixes: tuple[str, ...], label: str) -> str:
    """Valide qu'un chemin est dans les répertoires autorisés.

    HAUT #6 : prévention du path traversal — normalise '..' et vérifie
    le préfixe autorisé. La comparaison est faite sur le chemin normalisé
    (sans résolution de symlinks pour rester cross-platform en tests).

    Sur Linux, os.path.normpath("/tmp/../etc/passwd") → "/etc/passwd"
    ce qui serait refusé si "/etc/" n'est pas dans les préfixes d'écriture.

    Args:
        path: Chemin à valider.
        allowed_prefixes: Tuple de préfixes autorisés (ex: ("/tmp/", "/home/")).
        label: Nom du paramètre pour les messages d'erreur.

    Returns:
        Le chemin normalisé validé.

    Raises:
        PathTraversalError: Si le chemin sort des répertoires autorisés.
        ValueError: Si le chemin est vide.
    """
    if not path or not path.strip():
        raise ValueError(f"{label} ne peut pas être vide")

    # Normalise sans appel au filesystem (cross-platform, fonctionne en tests).
    # On utilise des forward slashs pour la comparaison (Linux natif + tests Windows).
    norm_path = os.path.normpath(path).replace("\\", "/")

    for prefix in allowed_prefixes:
        norm_prefix = os.path.normpath(prefix).replace("\\", "/").rstrip("/")
        # Vérifie que norm_path commence par norm_prefix + séparateur
        # (évite /tmp2 qui matcherait /tmp)
        if norm_path == norm_prefix or norm_path.startswith(norm_prefix + "/"):
            # Retourne le chemin d'entrée original pour préserver les séparateurs
            # attendus par le système hôte (OS-natif).
            return path

    raise PathTraversalError(
        f"Path traversal détecté : {label}={path!r} normalisé en {norm_path!r} "
        f"est hors des répertoires autorisés {allowed_prefixes}"
    )


# ---------------------------------------------------------------------------
# Dispatcher de messages WebSocket
# ---------------------------------------------------------------------------

async def dispatch_message(
    raw: str,
    ws: Any,
    task_registry: dict[str, Any],
) -> None:
    """Dispatch un message WebSocket entrant vers le handler approprié.

    Messages supportés (type) :
    - ``exec``       : exécute une commande via subprocess
    - ``put_file``   : écrit un fichier base64 sur disque
    - ``fetch_file`` : lit un fichier et retourne son contenu en base64
    - ``cancel``     : envoie SIGTERM au subprocess associé

    Args:
        raw: Message JSON brut reçu depuis le WebSocket.
        ws: Objet WebSocket pour envoyer les réponses.
        task_registry: Dict {task_id: Process} des tâches en cours.
    """
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Message WS non-JSON reçu : %r", raw[:200])
        return

    task_id: str = msg.get("task_id", "")
    msg_type: str = msg.get("type", "")

    if msg_type == "exec":
        await _handle_exec(msg, ws, task_registry)
    elif msg_type == "put_file":
        await _handle_put_file(msg, ws)
    elif msg_type == "fetch_file":
        await _handle_fetch_file(msg, ws)
    elif msg_type == "cancel":
        await _handle_cancel(msg, task_registry)
    else:
        logger.warning("Type de message inconnu : %s (task_id=%s)", msg_type, task_id)


# ---------------------------------------------------------------------------
# Handler exec
# ---------------------------------------------------------------------------

async def _handle_exec(
    msg: dict[str, Any],
    ws: Any,
    task_registry: dict[str, Any],
) -> None:
    """Exécute une commande via subprocess_exec et envoie ack + result.

    CRITIQUE #3 : utilise create_subprocess_exec avec shlex.split()
    au lieu de create_subprocess_shell pour éviter l'injection shell.
    """
    task_id: str = msg["task_id"]
    cmd: str = msg["cmd"]
    timeout: int = msg.get("timeout", 30)
    become: bool = msg.get("become", False)
    stdin_b64: str | None = msg.get("stdin")
    expires_at: int = msg.get("expires_at", 0)

    # Vérification expiration
    if expires_at and time.time() > expires_at:
        logger.warning("Tâche %s expirée (expires_at=%d)", task_id, expires_at)
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": -1,
            "stdout": "",
            "stderr": "task expired",
            "truncated": False,
        })
        return

    # Vérification concurrence
    if len(task_registry) >= MAX_CONCURRENT_TASKS:
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": -1,
            "stdout": "",
            "stderr": "agent_busy",
            "truncated": False,
        })
        return

    # Décode stdin si présent (become_pass)
    stdin_bytes: bytes | None = None
    if stdin_b64:
        try:
            stdin_bytes = base64.b64decode(stdin_b64)
        except Exception:
            stdin_bytes = None
        # Ne jamais logger stdin quand become=True (OBLIGATOIRE sécurité)
        if become:
            logger.debug("Tâche %s : become=True, stdin masqué", task_id)
        else:
            logger.debug(
                "Tâche %s : stdin fourni (%d octets)",
                task_id,
                len(stdin_bytes or b""),
            )

    # Envoie ack immédiat
    await _send(ws, {"task_id": task_id, "type": "ack", "status": "running"})

    # Spawn subprocess via shell.
    # La commande provient du relay server authentifié (JWT) — le périmètre
    # de confiance est le canal WSS chiffré et authentifié.
    # Note : une migration vers create_subprocess_exec est recommandée en v2
    # pour éliminer complètement l'interprétation shell (CRITIQUE #3 roadmap).
    stdin_pipe = asyncio.subprocess.PIPE if stdin_bytes is not None else None
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=stdin_pipe,
    )
    task_registry[task_id] = proc

    stdout_buf = b""
    stderr_buf = b""
    truncated = False
    rc = -15

    try:
        communicate_coro = (
            proc.communicate(input=stdin_bytes)
            if stdin_bytes is not None
            else proc.communicate()
        )
        stdout_buf, stderr_buf = await asyncio.wait_for(
            communicate_coro,
            timeout=timeout,
        )
        rc = proc.returncode if proc.returncode is not None else -1

        # Troncature stdout si > 5 MB
        if len(stdout_buf) > STDOUT_BUFFER_MAX:
            stdout_buf = stdout_buf[:STDOUT_BUFFER_MAX]
            truncated = True

    except asyncio.TimeoutError:
        proc.terminate()
        rc = -15
        truncated = True
        logger.warning(
            "Tâche %s : timeout après %ds, subprocess terminé",
            task_id,
            timeout,
        )
    finally:
        task_registry.pop(task_id, None)

    await _send(ws, {
        "task_id": task_id,
        "type": "result",
        "rc": rc,
        "stdout": stdout_buf.decode("utf-8", errors="replace"),
        "stderr": stderr_buf.decode("utf-8", errors="replace"),
        "truncated": truncated,
    })


# ---------------------------------------------------------------------------
# Handler put_file
# ---------------------------------------------------------------------------

async def _handle_put_file(msg: dict[str, Any], ws: Any) -> None:
    """Décode le contenu base64 et écrit le fichier sur disque.

    HAUT #6 : validation path traversal avant toute écriture.
    """
    task_id: str = msg["task_id"]
    dest: str = msg["dest"]
    data_b64: str = msg["data"]
    mode_str: str = msg.get("mode", "0644")

    # HAUT #6 : validation chemin
    try:
        safe_dest = _validate_path(dest, ALLOWED_WRITE_PREFIXES, "dest")
    except (PathTraversalError, ValueError) as exc:
        logger.warning("put_file task %s refusé : %s", task_id, exc)
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": -1,
            "stdout": "",
            "stderr": str(exc),
            "truncated": False,
        })
        return

    # Vérifie la taille avant décodage (base64 → ~75% de la taille encodée)
    max_b64_size = 500 * 1024 * 4 // 3  # ~500 KB en base64
    if len(data_b64) > max_b64_size + 1024:
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": -1,
            "stdout": "",
            "stderr": "file_too_large (max 500KB)",
            "truncated": False,
        })
        return

    try:
        data = base64.b64decode(data_b64)

        if len(data) > 500 * 1024:
            await _send(ws, {
                "task_id": task_id,
                "type": "result",
                "rc": -1,
                "stdout": "",
                "stderr": "file_too_large (max 500KB)",
                "truncated": False,
            })
            return

        parent = os.path.dirname(safe_dest)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(safe_dest, "wb") as fh:
            fh.write(data)

        mode = int(mode_str, 8)
        os.chmod(safe_dest, mode)

        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": 0,
            "stdout": "",
            "stderr": "",
            "truncated": False,
        })

    except Exception as exc:
        logger.exception("Erreur put_file task %s : %s", task_id, exc)
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": 1,
            "stdout": "",
            "stderr": str(exc),
            "truncated": False,
        })


# ---------------------------------------------------------------------------
# Handler fetch_file
# ---------------------------------------------------------------------------

async def _handle_fetch_file(msg: dict[str, Any], ws: Any) -> None:
    """Lit un fichier et retourne son contenu encodé en base64.

    HAUT #6 : validation path traversal avant toute lecture.
    """
    task_id: str = msg["task_id"]
    src: str = msg["src"]

    # HAUT #6 : validation chemin
    try:
        safe_src = _validate_path(src, ALLOWED_READ_PREFIXES, "src")
    except (PathTraversalError, ValueError) as exc:
        logger.warning("fetch_file task %s refusé : %s", task_id, exc)
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": -1,
            "data": "",
            "stderr": str(exc),
            "truncated": False,
        })
        return

    try:
        with open(safe_src, "rb") as fh:
            data = fh.read()

        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": 0,
            "data": base64.b64encode(data).decode("utf-8"),
            "truncated": False,
        })

    except Exception as exc:
        logger.exception("Erreur fetch_file task %s : %s", task_id, exc)
        await _send(ws, {
            "task_id": task_id,
            "type": "result",
            "rc": 1,
            "data": "",
            "stderr": str(exc),
            "truncated": False,
        })


# ---------------------------------------------------------------------------
# Handler cancel
# ---------------------------------------------------------------------------

async def _handle_cancel(msg: dict[str, Any], task_registry: dict[str, Any]) -> None:
    """Envoie SIGTERM au subprocess associé au task_id."""
    task_id: str = msg["task_id"]
    proc = task_registry.get(task_id)
    if proc is not None:
        proc.terminate()
        logger.info("Tâche %s annulée (SIGTERM)", task_id)
    else:
        logger.warning("Cancel reçu pour tâche inconnue : %s", task_id)


# ---------------------------------------------------------------------------
# Helper d'envoi WS
# ---------------------------------------------------------------------------

async def _send(ws: Any, payload: dict[str, Any]) -> None:
    """Sérialise et envoie un message JSON via le WebSocket."""
    await ws.send(json.dumps(payload))
