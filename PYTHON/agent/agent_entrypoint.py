"""
agent_entrypoint.py — Point d'entrée de l'agent pour le déploiement Docker qualif.

Simule le comportement du service systemd relay-agent.service :
1. Génère la clef RSA-4096 si absente (lib cryptography, format SubjectPublicKeyInfo)
2. Tente l'enrollment POST /api/register avec déchiffrement OAEP-SHA256
3. Si enrollment échoue (serveur absent ou non autorisé), démarre la boucle
   de reconnexion avec backoff exponentiel
4. Connecte le WebSocket et dispatche les messages

Variables d'environnement :
  RELAY_SERVER_URL   : URL du relay server (ex: https://relay.example.com)
  RELAY_HOSTNAME     : hostname de l'agent (défaut: socket.gethostname())
  RELAY_DATA_DIR     : répertoire des données persistées (défaut: /var/lib/relay-agent)
"""

import asyncio
import base64
import logging
import os
import socket
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("relay-agent")

RELAY_SERVER_URL = os.environ.get("RELAY_SERVER_URL", "https://relay.qualif:8443")
RELAY_HOSTNAME = os.environ.get("RELAY_HOSTNAME", socket.gethostname())
RELAY_DATA_DIR = os.environ.get("RELAY_DATA_DIR", "/var/lib/relay-agent")
RELAY_CA_BUNDLE = os.environ.get("RELAY_CA_BUNDLE", None)

PRIVATE_KEY_PATH = os.path.join(RELAY_DATA_DIR, "private_key.pem")
JWT_PATH = os.path.join(RELAY_DATA_DIR, "token.jwt")

REGISTER_URL = f"{RELAY_SERVER_URL}/api/register"
WS_URL = RELAY_SERVER_URL.replace("https://", "wss://").replace("http://", "ws://") + "/ws/agent"


def generate_or_load_rsa_key():
    """
    Génère la clef RSA-4096 ou charge celle existante depuis RELAY_DATA_DIR.

    Utilise la lib cryptography (SubjectPublicKeyInfo PEM, compatible serveur).
    Retourne (private_key, public_key_pem_str).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv_path = Path(PRIVATE_KEY_PATH)
    pub_path = Path(PRIVATE_KEY_PATH.replace("private_key.pem", "public_key.pem"))

    if priv_path.exists():
        logger.info("Clef RSA existante chargée depuis %s", PRIVATE_KEY_PATH)
        priv_pem = priv_path.read_bytes()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_key, pub_pem

    logger.info("Génération clef RSA-4096 (première exécution)...")
    t0 = time.time()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elapsed = time.time() - t0
    logger.info("Clef RSA-4096 générée en %.1fs", elapsed)

    # Sérialise la clef privée (PEM PKCS8, non chiffrée)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Persiste clef privée avec permissions 600
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_pem)
    logger.info("Clef privée persistée → %s (mode 600)", PRIVATE_KEY_PATH)

    # Sérialise et persiste clef publique (SubjectPublicKeyInfo — compatible serveur)
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    pub_path.write_text(pub_pem)
    logger.info("Clef publique persistée → %s (SubjectPublicKeyInfo)", str(pub_path))

    return private_key, pub_pem


async def enroll_with_oaep(register_url: str, hostname: str, pub_pem: str, private_key) -> str:
    """
    Enrollment POST /api/register avec déchiffrement RSA-OAEP-SHA256.

    Compatible avec le serveur qui chiffre avec cryptography/OAEP-SHA256.
    La lib rsa (PKCS#1 v1.5) est incompatible avec ce schéma.

    Returns:
        JWT string déchiffré.

    Raises:
        Exception si enrollment refusé ou déchiffrement échoué.
    """
    import httpx
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    verify: str | bool = RELAY_CA_BUNDLE if RELAY_CA_BUNDLE else True

    async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
        r = await client.post(
            register_url,
            json={"hostname": hostname, "public_key_pem": pub_pem},
        )

    if r.status_code != 200:
        raise Exception(
            f"Enrollment refusé : HTTP {r.status_code} — {r.text[:200]}"
        )

    data = r.json()
    ciphertext = base64.b64decode(data["token_encrypted"])

    jwt_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return jwt_bytes.decode("utf-8")


async def run():
    """Boucle principale : enrollment + reconnexion WS avec backoff."""
    sys.path.insert(0, "/opt/relay-agent")
    from relay_agent import EnrollmentError, ReconnectManager, store_jwt, dispatch_message

    logger.info("=== relay-agent démarrage ===")
    logger.info("Hostname  : %s", RELAY_HOSTNAME)
    logger.info("Server    : %s", RELAY_SERVER_URL)
    logger.info("Data dir  : %s", RELAY_DATA_DIR)

    # Étape 1 — Génération / chargement clef RSA
    private_key, pub_pem = generate_or_load_rsa_key()

    reconnect = ReconnectManager(base_delay=1.0, max_delay=60.0)

    # Étape 2 — Boucle enrollment + connexion WS
    while True:
        jwt_path = Path(JWT_PATH)
        jwt_token = None

        if jwt_path.exists():
            jwt_token = jwt_path.read_text().strip()
            logger.info("JWT existant chargé depuis %s", JWT_PATH)
        else:
            logger.info("Tentative enrollment → POST %s", REGISTER_URL)
            try:
                jwt_token = await enroll_with_oaep(
                    register_url=REGISTER_URL,
                    hostname=RELAY_HOSTNAME,
                    pub_pem=pub_pem,
                    private_key=private_key,
                )
                store_jwt(jwt_token, JWT_PATH)
                logger.info("Enrollment réussi — JWT persisté → %s", JWT_PATH)
                reconnect.reset()
            except Exception as exc:
                delay = reconnect.next_delay()
                logger.warning(
                    "Enrollment échoué : %s — retry dans %.0fs", exc, delay
                )
                await asyncio.sleep(delay)
                continue

        # Connexion WebSocket
        logger.info("Connexion WS → %s", WS_URL)
        try:
            import websockets

            ssl_ctx = None
            if WS_URL.startswith("wss://"):
                import ssl
                ssl_ctx = ssl.create_default_context(cafile=RELAY_CA_BUNDLE)
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED

            headers = {"Authorization": f"Bearer {jwt_token}"}
            async with websockets.connect(WS_URL, additional_headers=headers, ssl=ssl_ctx) as ws:
                reconnect.reset()
                logger.info("WebSocket connecté — en attente de tâches")
                task_registry: dict = {}
                async for raw in ws:
                    await dispatch_message(raw, ws, task_registry)

        except Exception as exc:
            close_code = 0
            if hasattr(exc, "rcvd") and exc.rcvd is not None:
                close_code = getattr(exc.rcvd, "code", 0)
            if not reconnect.should_reconnect(close_code):
                logger.error("Token révoqué (4001) — arrêt définitif")
                sys.exit(1)
            delay = reconnect.next_delay()
            logger.warning("Connexion WS perdue : %s — retry dans %.0fs", exc, delay)
            # Efface le JWT si erreur 4002 (token expiré)
            if close_code == 4002:
                logger.info("Token expiré (4002) — suppression JWT pour re-enrollment")
                jwt_path.unlink(missing_ok=True)
            await asyncio.sleep(delay)


if __name__ == "__main__":
    asyncio.run(run())
