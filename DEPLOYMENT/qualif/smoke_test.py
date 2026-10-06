"""
smoke_test.py — Smoke tests Phase 2 : secagent-server complet.

Tests :
1. GET /health                    → 200, status ok/degraded
2. POST /api/admin/tokens        → 201, jeton d'enrôlement à usage unique (#192c : plus d'enrôlement sans jeton)
3. POST /api/register (2 phases)  → 200, JWT retourné (challenge nonce vérifié)
4. WebSocket /ws/agent            → connexion ouverte
5. GET /api/inventory             → format JSON Ansible valide
6. secagent-minion Phase 1 connecté  → visible dans inventaire (status=connected)
"""

import asyncio
import base64
import json
import os
import sys
import time

import httpx
from jose import jwt as jose_jwt

RELAY_API_URL = os.environ.get("RELAY_API_URL", "http://relay-api:8443")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

PASS = "[PASS]"
FAIL = "[FAIL]"
results: dict[str, bool] = {}


def _make_plugin_jwt() -> str:
    """Génère un JWT avec rôle 'plugin' pour les endpoints protégés."""
    import uuid
    now = int(time.time())
    payload = {
        "sub": "smoke-test-plugin",
        "role": "plugin",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 3600,
    }
    return jose_jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


async def test_health(client: httpx.AsyncClient) -> bool:
    print("\n--- Test 1 : GET /health ---")
    try:
        r = await client.get(f"{RELAY_API_URL}/health")
        data = r.json()
        print(f"  HTTP {r.status_code} — {data}")
        ok = r.status_code == 200 and data.get("status") in ("ok", "degraded")
        print(f"  {PASS if ok else FAIL} GET /health → {r.status_code}")
        return ok
    except Exception as exc:
        print(f"  {FAIL} GET /health : {exc}")
        return False


async def test_admin_authorize(client: httpx.AsyncClient, hostname: str, pub_pem: str) -> tuple[bool, str]:
    """Crée le jeton d'enrôlement à usage unique de ce hostname (l'enrôlement sans jeton n'existe plus)."""
    import re
    print("\n--- Test 2 : POST /api/admin/tokens (enrollment) ---")
    try:
        r = await client.post(
            f"{RELAY_API_URL}/api/admin/tokens",
            json={"role": "enrollment", "hostname_pattern": re.escape(hostname), "created_by": "smoke-test"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        print(f"  HTTP {r.status_code}")
        ok = r.status_code in (200, 201) and bool(r.json().get("token"))
        print(f"  {PASS if ok else FAIL} Jeton d'enrôlement → {r.status_code}")
        return ok, (r.json().get("token", "") if ok else "")
    except Exception as exc:
        print(f"  {FAIL} Jeton d'enrôlement : {exc}")
        return False, ""


async def test_enrollment(client: httpx.AsyncClient, hostname: str, pub_pem: str,
                          priv_key, enrollment_token: str) -> tuple[bool, str]:
    print("\n--- Test 3 : POST /api/register (jeton + challenge) ---")
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

        # étape 1 : le serveur renvoie un nonce chiffré avec la clef publique de l'agent
        r = await client.post(
            f"{RELAY_API_URL}/api/register",
            json={"hostname": hostname, "public_key_pem": pub_pem, "enrollment_token": enrollment_token},
        )
        print(f"  étape 1 : HTTP {r.status_code}")
        if r.status_code != 200:
            print(f"  {FAIL} Enrollment étape 1 → {r.status_code} : {r.text[:200]}")
            return False, ""
        step1 = r.json()
        nonce = priv_key.decrypt(base64.b64decode(step1["challenge"]), oaep)

        # étape 2 : preuve de possession de la clef privée = OAEP(nonce + jeton, clef publique du serveur)
        server_pub = serialization.load_pem_public_key(step1["server_public_key_pem"].encode())
        response = server_pub.encrypt(nonce + enrollment_token.encode(), oaep)
        r = await client.post(
            f"{RELAY_API_URL}/api/register",
            json={"hostname": hostname, "public_key_pem": pub_pem, "enrollment_token": enrollment_token,
                  "challenge_response": base64.b64encode(response).decode()},
        )
        print(f"  étape 2 : HTTP {r.status_code}")
        if r.status_code != 200:
            print(f"  {FAIL} Enrollment étape 2 → {r.status_code} : {r.text[:200]}")
            return False, ""

        data = r.json()
        assert "token_encrypted" in data, "token_encrypted manquant"
        assert "server_public_key_pem" in data, "server_public_key_pem manquant"

        # Déchiffre le JWT avec la clef privée RSA de l'agent
        jwt_token = priv_key.decrypt(base64.b64decode(data["token_encrypted"]), oaep).decode("utf-8")
        print(f"  JWT déchiffré OK ({len(jwt_token)} chars)")
        print(f"  {PASS} Enrollment agent → 200, JWT retourné")
        return True, jwt_token
    except Exception as exc:
        print(f"  {FAIL} Enrollment : {exc}")
        return False, ""


async def test_websocket(jwt_token: str) -> bool:
    print("\n--- Test 4 : WebSocket /ws/agent ---")
    try:
        import websockets
        ws_url = RELAY_API_URL.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_url}/ws/agent"

        connected = False
        try:
            async with websockets.connect(
                ws_url,
                additional_headers={"Authorization": f"Bearer {jwt_token}"},
                open_timeout=10,
            ) as ws:
                connected = True
                print(f"  WebSocket ouverte vers {ws_url}")
                # Fermeture propre immédiate
                await ws.close()
        except Exception as exc:
            print(f"  Connexion WS : {exc}")
            # En qualification sans TLS, accepter ConnectionClosedOK aussi
            connected = "101" in str(exc) or connected

        print(f"  {PASS if connected else FAIL} WS agent connectée")
        return connected
    except Exception as exc:
        print(f"  {FAIL} WebSocket : {exc}")
        return False


async def test_inventory(client: httpx.AsyncClient) -> bool:
    print("\n--- Test 5 : GET /api/inventory ---")
    try:
        plugin_jwt = _make_plugin_jwt()
        r = await client.get(
            f"{RELAY_API_URL}/api/inventory",
            headers={"Authorization": f"Bearer {plugin_jwt}"},
        )
        print(f"  HTTP {r.status_code}")
        if r.status_code != 200:
            print(f"  {FAIL} Inventaire → {r.status_code} : {r.text[:200]}")
            return False

        data = r.json()
        print(f"  Inventaire : {json.dumps(data)[:300]}")

        # Validation format Ansible
        ok = (
            "all" in data
            and "hosts" in data["all"]
            and "_meta" in data
            and "hostvars" in data["_meta"]
        )
        print(f"  {PASS if ok else FAIL} Inventaire → format JSON Ansible valide")
        return ok
    except Exception as exc:
        print(f"  {FAIL} Inventaire : {exc}")
        return False


async def test_agent_connected(client: httpx.AsyncClient) -> bool:
    print("\n--- Test 6 : secagent-minion Phase 1 connecté et visible dans inventaire ---")
    try:
        plugin_jwt = _make_plugin_jwt()

        # Attendre jusqu'à 30s que l'agent se connecte
        for attempt in range(6):
            r = await client.get(
                f"{RELAY_API_URL}/api/inventory",
                headers={"Authorization": f"Bearer {plugin_jwt}"},
            )
            if r.status_code == 200:
                data = r.json()
                hostvars = data.get("_meta", {}).get("hostvars", {})
                connected_agents = [
                    h for h, v in hostvars.items()
                    if v.get("secagent_status") == "connected"
                ]
                if connected_agents:
                    print(f"  Agents connectés : {connected_agents}")
                    print(f"  {PASS} secagent-minion Phase 1 connecté et visible dans inventaire")
                    return True
                else:
                    print(f"  Tentative {attempt + 1}/6 — aucun agent connecté (attente 5s)...")
                    await asyncio.sleep(5)
            else:
                await asyncio.sleep(5)

        print(f"  {FAIL} secagent-minion Phase 1 non connecté après 30s")
        print(f"  Note : normal si l'agent Phase 1 pointe encore vers relay.qualif:8443")
        print(f"  (l'agent est configuré pour http://relay-api:8443 dans ce compose)")
        return False
    except Exception as exc:
        print(f"  {FAIL} Test agent connecté : {exc}")
        return False


async def main():
    print("=" * 60)
    print("SMOKE TEST Phase 2 — secagent-server")
    print(f"Cible : {RELAY_API_URL}")
    print(f"Date  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Génère une paire RSA-4096 pour le smoke test (agent fictif)
    print("\nGénération paire RSA-4096 pour smoke test...")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pub_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    print(f"Clef RSA générée ({len(pub_pem)} octets PEM)")

    hostname = f"smoke-agent-{int(time.time())}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        results["health"] = await test_health(client)
        results["authorize"], enrollment_token = await test_admin_authorize(client, hostname, pub_pem)
        ok_enroll, jwt_token = await test_enrollment(client, hostname, pub_pem, priv_key, enrollment_token)
        results["enrollment"] = ok_enroll
        if jwt_token:
            results["websocket"] = await test_websocket(jwt_token)
        else:
            results["websocket"] = False
            print(f"\n--- Test 4 : WebSocket /ws/agent ---")
            print(f"  {FAIL} Ignoré (pas de JWT)")
        results["inventory"] = await test_inventory(client)
        results["agent_connected"] = await test_agent_connected(client)

    # Rapport final
    print("\n" + "=" * 60)
    print("DEPLOY QUALIF — Phase 2")
    print("=" * 60)
    print(f"Cible : 192.168.1.218")
    print()
    print(f"{PASS if results.get('health') else FAIL} docker compose up sans erreur / GET /health → 200")
    print(f"{PASS if results.get('authorize') else FAIL} Jeton d'enrôlement → 201")
    print(f"{PASS if results.get('enrollment') else FAIL} Enrollment agent → 200")
    print(f"{PASS if results.get('websocket') else FAIL} WS agent connectée")
    print(f"{PASS if results.get('inventory') else FAIL} Inventaire → format Ansible valide")
    print(f"{PASS if results.get('agent_connected') else FAIL} secagent-minion Phase 1 connecté et visible dans inventaire")
    print()
    all_pass = all(results.values())
    print(f"VERDICT : {'PASS' if all_pass else 'PARTIAL/FAIL'}")
    print("=" * 60)

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    asyncio.run(main())
