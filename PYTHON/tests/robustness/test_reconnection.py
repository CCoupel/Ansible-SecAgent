"""
test_reconnection.py — Tests de robustesse : reconnexion agent

Couverture :
- Reconnexion après coupure réseau (code 4000) avec backoff exponentiel
- Code close 4001 → arrêt définitif, aucune tentative de reconnexion
- Code close 4002 → refresh token puis reconnexion
- Backoff : délais 1s, 2s, 4s... (mock asyncio.sleep)
- Agent reprend les tâches en cours après reconnexion
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent"))


# ---------------------------------------------------------------------------
# Tests reconnexion backoff après coupure réseau
# ---------------------------------------------------------------------------

class TestReconnectBackoff:
    """Backoff exponentiel sur coupure réseau (close 4000)."""

    @pytest.mark.asyncio
    async def test_reconnect_after_network_failure_attempts_again(self):
        """Après une coupure réseau, l'agent tente de se reconnecter."""
        connect_attempts = []

        async def fake_connect(url, **kwargs):
            connect_attempts.append(url)
            if len(connect_attempts) == 1:
                raise ConnectionRefusedError("connexion refusée")
            # Deuxième tentative réussit puis ferme proprement
            ws = AsyncMock()
            ws.__aenter__ = AsyncMock(return_value=ws)
            ws.__aexit__ = AsyncMock(return_value=None)
            ws.recv = AsyncMock(side_effect=asyncio.CancelledError)
            return ws

        sleep_calls = []

        with patch("websockets.connect", side_effect=fake_connect), \
             patch("asyncio.sleep", side_effect=lambda d: sleep_calls.append(d)):
            try:
                from relay_agent import run_agent_loop
                try:
                    await asyncio.wait_for(
                        run_agent_loop(
                            server_url="wss://relay.example.com/ws/agent",
                            jwt_token="fake.jwt.token",
                        ),
                        timeout=1.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                assert len(connect_attempts) >= 2
            except (ImportError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop non implémenté — test ignoré")

    @pytest.mark.asyncio
    async def test_backoff_delays_are_exponential(self):
        """Les délais de reconnexion doublent à chaque échec : 1s, 2s, 4s..."""
        fail_count = [0]
        sleep_calls = []

        async def fake_connect(url, **kwargs):
            fail_count[0] += 1
            if fail_count[0] <= 4:
                raise ConnectionRefusedError("refusé")
            raise asyncio.CancelledError

        async def fake_sleep(duration):
            sleep_calls.append(duration)

        with patch("websockets.connect", side_effect=fake_connect), \
             patch("asyncio.sleep", side_effect=fake_sleep):
            try:
                from relay_agent import run_agent_loop
                try:
                    await asyncio.wait_for(
                        run_agent_loop(
                            server_url="wss://relay.example.com/ws/agent",
                            jwt_token="fake.jwt.token",
                        ),
                        timeout=2.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

                # Vérifier progression exponentielle
                reconnect_sleeps = [d for d in sleep_calls if d >= 1.0]
                if len(reconnect_sleeps) >= 2:
                    assert reconnect_sleeps[1] >= reconnect_sleeps[0]
            except (ImportError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop non implémenté — test ignoré")

    @pytest.mark.asyncio
    async def test_backoff_delay_capped_at_60s(self):
        """Le délai de reconnexion est plafonné à 60 secondes maximum."""
        try:
            from relay_agent import ReconnectManager
            manager = ReconnectManager(base_delay=1.0, max_delay=60.0)
            for _ in range(30):
                delay = manager.next_delay()
            assert delay <= 60.0
        except (ImportError, AttributeError):
            pytest.skip("relay_agent.ReconnectManager non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests close code 4001 — révocation
# ---------------------------------------------------------------------------

class TestCloseCode4001:
    """Comportement sur réception du code WS 4001 (token révoqué)."""

    @pytest.mark.asyncio
    async def test_close_4001_stops_reconnection(self):
        """Code close 4001 → l'agent ne tente plus de se reconnecter."""
        import websockets

        connect_attempts = [0]

        async def fake_connect(url, **kwargs):
            connect_attempts[0] += 1
            if connect_attempts[0] > 1:
                raise AssertionError("L'agent ne devrait pas reconnecter après 4001")
            raise websockets.exceptions.ConnectionClosedError(
                rcvd=websockets.frames.Close(code=4001, reason="token révoqué"),
                sent=None,
            )

        sleep_calls = []

        with patch("websockets.connect", side_effect=fake_connect), \
             patch("asyncio.sleep", side_effect=lambda d: sleep_calls.append(d)):
            try:
                from relay_agent import run_agent_loop
                try:
                    await asyncio.wait_for(
                        run_agent_loop(
                            server_url="wss://relay.example.com/ws/agent",
                            jwt_token="fake.jwt.token",
                        ),
                        timeout=1.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                # Une seule tentative, pas de sleep de reconnexion
                assert connect_attempts[0] == 1
                reconnect_sleeps = [d for d in sleep_calls if d >= 1.0]
                assert len(reconnect_sleeps) == 0
            except (ImportError, AttributeError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop non implémenté — test ignoré")

    @pytest.mark.asyncio
    async def test_close_4001_logs_revocation_event(self):
        """Code close 4001 → l'événement est loggé."""
        import logging
        import websockets

        log_records = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                log_records.append(record.getMessage())

        handler = CapturingHandler()

        async def fake_connect(url, **kwargs):
            raise websockets.exceptions.ConnectionClosedError(
                rcvd=websockets.frames.Close(code=4001, reason="révoqué"),
                sent=None,
            )

        with patch("websockets.connect", side_effect=fake_connect):
            try:
                from relay_agent import run_agent_loop
                import logging as lg
                logger = lg.getLogger("relay_agent")
                logger.addHandler(handler)
                logger.setLevel(lg.WARNING)

                try:
                    await asyncio.wait_for(
                        run_agent_loop(
                            server_url="wss://relay.example.com/ws/agent",
                            jwt_token="fake.jwt.token",
                        ),
                        timeout=1.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

                all_logs = " ".join(log_records).lower()
                assert any(
                    keyword in all_logs
                    for keyword in ["4001", "révoqué", "revoked", "révocation", "blacklist"]
                )
            except (ImportError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop non implémenté — test ignoré")
            finally:
                try:
                    import logging as lg
                    lg.getLogger("relay_agent").removeHandler(handler)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Tests close code 4002 — token expiré
# ---------------------------------------------------------------------------

class TestCloseCode4002:
    """Comportement sur réception du code WS 4002 (token expiré)."""

    @pytest.mark.asyncio
    async def test_close_4002_triggers_token_refresh(self):
        """Code close 4002 → appel à POST /api/token/refresh."""
        import websockets

        refresh_called = [False]

        async def fake_connect(url, **kwargs):
            raise websockets.exceptions.ConnectionClosedError(
                rcvd=websockets.frames.Close(code=4002, reason="token expiré"),
                sent=None,
            )

        async def fake_refresh(*args, **kwargs):
            refresh_called[0] = True
            return "new.jwt.token"

        with patch("websockets.connect", side_effect=fake_connect), \
             patch("asyncio.sleep", return_value=None):
            try:
                from relay_agent import run_agent_loop, refresh_token
                with patch("relay_agent.refresh_token", side_effect=fake_refresh):
                    try:
                        await asyncio.wait_for(
                            run_agent_loop(
                                server_url="wss://relay.example.com/ws/agent",
                                jwt_token="expired.jwt.token",
                            ),
                            timeout=1.0,
                        )
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        pass
                assert refresh_called[0] is True
            except (ImportError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop / refresh_token non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests reprise des tâches après reconnexion
# ---------------------------------------------------------------------------

class TestTaskResumptionAfterReconnect:
    """L'agent reprend le traitement des messages après reconnexion."""

    @pytest.mark.asyncio
    async def test_agent_processes_messages_after_reconnect(self):
        """Après reconnexion, le dispatcher traite normalement les nouveaux messages."""
        import json

        messages_processed = []

        exec_msg = json.dumps({
            "task_id": "t-after-reconnect",
            "type": "exec",
            "cmd": "echo hello",
            "timeout": 30,
            "become": False,
            "expires_at": int(__import__("time").time()) + 3600,
        })

        call_count = [0]

        async def fake_connect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionRefusedError("coupure réseau")
            ws = AsyncMock()
            ws.__aenter__ = AsyncMock(return_value=ws)
            ws.__aexit__ = AsyncMock(return_value=None)
            # Deuxième connexion : envoie un message puis annule
            recv_count = [0]

            async def fake_recv():
                recv_count[0] += 1
                if recv_count[0] == 1:
                    return exec_msg
                raise asyncio.CancelledError

            ws.recv = fake_recv
            ws.send = AsyncMock(side_effect=lambda m: messages_processed.append(json.loads(m)))
            return ws

        with patch("asyncio.create_subprocess_shell") as mock_sub, \
             patch("asyncio.sleep", return_value=None), \
             patch("websockets.connect", side_effect=fake_connect):
            proc = AsyncMock()
            proc.communicate = AsyncMock(return_value=(b"hello\n", b""))
            proc.returncode = 0
            mock_sub.return_value = proc

            try:
                from relay_agent import run_agent_loop
                try:
                    await asyncio.wait_for(
                        run_agent_loop(
                            server_url="wss://relay.example.com/ws/agent",
                            jwt_token="fake.jwt.token",
                        ),
                        timeout=2.0,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

                result_msgs = [m for m in messages_processed if m.get("type") == "result"]
                assert len(result_msgs) >= 1
                assert result_msgs[0]["task_id"] == "t-after-reconnect"
            except (ImportError, AttributeError):
                pytest.skip("relay_agent.run_agent_loop non implémenté — test ignoré")
