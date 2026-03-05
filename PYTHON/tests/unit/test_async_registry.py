"""
test_async_registry.py — Tests unitaires pour async_registry.py

Couverture :
- register_job + get_job : aller-retour disque (sauvegarde et lecture)
- PID mort → check_job_alive retourne False
- PID vivant → check_job_alive retourne True
- Reprise après redémarrage agent : PID mort → job marqué finished=True, rc=-1
- Reprise après redémarrage agent : PID vivant → job conservé tel quel
- Timeout dépassé → job killed (SIGTERM), rc=-15
- async_status : job en cours → finished=0
- async_status : job terminé → finished=1 avec rc
- Nettoyage des jobs expirés
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_jobs_file(tmp_path):
    """Chemin temporaire pour le fichier de registre async."""
    return str(tmp_path / "async_jobs.json")


@pytest.fixture
def sample_job():
    """Un job async de test."""
    return {
        "jid": "jid-test-001",
        "pid": 99999,
        "cmd": "./deploy.sh",
        "started_at": time.time(),
        "timeout": 3600,
        "stdout_path": "/tmp/.ansible-relay/jid-test-001.stdout",
        "finished": False,
        "rc": None,
    }


# ---------------------------------------------------------------------------
# Tests register_job / get_job
# ---------------------------------------------------------------------------

class TestRegisterAndGetJob:
    """Tests de sauvegarde et lecture du registre sur disque."""

    def test_register_job_creates_file(self, tmp_jobs_file, sample_job):
        """register_job crée le fichier de registre s'il n'existe pas."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            assert os.path.exists(tmp_jobs_file)
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_register_job_persists_to_disk(self, tmp_jobs_file, sample_job):
        """register_job écrit le job dans le fichier JSON."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            with open(tmp_jobs_file) as f:
                data = json.load(f)
            assert sample_job["jid"] in data
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_get_job_returns_registered_job(self, tmp_jobs_file, sample_job):
        """get_job retourne le job précédemment enregistré."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            job = registry.get_job(sample_job["jid"])
            assert job is not None
            assert job["jid"] == sample_job["jid"]
            assert job["pid"] == sample_job["pid"]
            assert job["cmd"] == sample_job["cmd"]
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_get_job_unknown_jid_returns_none(self, tmp_jobs_file):
        """get_job sur un jid inconnu retourne None."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            result = registry.get_job("nonexistent-jid")
            assert result is None
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_register_multiple_jobs(self, tmp_jobs_file):
        """Plusieurs jobs peuvent coexister dans le registre."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            for i in range(3):
                registry.register_job(
                    jid=f"jid-{i}",
                    pid=10000 + i,
                    cmd=f"./task-{i}.sh",
                    timeout=3600,
                    stdout_path=f"/tmp/.ansible-relay/jid-{i}.stdout",
                )
            for i in range(3):
                job = registry.get_job(f"jid-{i}")
                assert job is not None
                assert job["pid"] == 10000 + i
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_registry_loads_from_existing_file(self, tmp_jobs_file, sample_job):
        """Un nouveau registre chargé depuis un fichier existant retrouve les jobs précédents."""
        try:
            from async_registry import AsyncRegistry
            # Premier registre : enregistre un job
            registry1 = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry1.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            # Deuxième registre : charge depuis le même fichier
            registry2 = AsyncRegistry(jobs_file=tmp_jobs_file)
            job = registry2.get_job(sample_job["jid"])
            assert job is not None
            assert job["jid"] == sample_job["jid"]
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests check_job_alive
# ---------------------------------------------------------------------------

class TestCheckJobAlive:
    """Tests de vérification de l'état du PID."""

    def test_dead_pid_returns_false(self, tmp_jobs_file, sample_job):
        """PID inexistant → check_job_alive retourne False."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=99999,  # PID très probablement inexistant
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            # Mock os.kill pour simuler ProcessLookupError
            with patch("os.kill", side_effect=ProcessLookupError("no such process")):
                alive = registry.check_job_alive(sample_job["jid"])
            assert alive is False
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_alive_pid_returns_true(self, tmp_jobs_file, sample_job):
        """PID actif → check_job_alive retourne True."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            # Mock os.kill avec signal 0 (test d'existence) → pas d'exception = vivant
            with patch("os.kill", return_value=None):
                alive = registry.check_job_alive(sample_job["jid"])
            assert alive is True
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")

    def test_permission_error_treated_as_alive(self, tmp_jobs_file, sample_job):
        """PermissionError sur os.kill(pid, 0) = processus existe mais inaccessible → vivant."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            with patch("os.kill", side_effect=PermissionError("not permitted")):
                alive = registry.check_job_alive(sample_job["jid"])
            assert alive is True
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests reprise après redémarrage agent
# ---------------------------------------------------------------------------

class TestRestoreOnRestart:
    """Tests de la reprise des jobs au redémarrage de l'agent."""

    def test_dead_pid_on_restart_marks_job_finished(self, tmp_jobs_file, sample_job):
        """Au redémarrage, PID mort → job marqué finished=True, rc=-1."""
        # Préparer un fichier de registre avec un job "en cours"
        jobs_data = {
            sample_job["jid"]: {
                **sample_job,
                "finished": False,
                "rc": None,
            }
        }
        with open(tmp_jobs_file, "w") as f:
            json.dump(jobs_data, f)

        try:
            from async_registry import AsyncRegistry
            with patch("os.kill", side_effect=ProcessLookupError("no such process")):
                registry = AsyncRegistry(jobs_file=tmp_jobs_file)
                registry.restore_on_restart()

            job = registry.get_job(sample_job["jid"])
            assert job["finished"] is True
            assert job["rc"] == -1
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.restore_on_restart non implémenté — test ignoré")

    def test_alive_pid_on_restart_keeps_job_running(self, tmp_jobs_file, sample_job):
        """Au redémarrage, PID vivant → job conservé en cours (finished=False)."""
        jobs_data = {
            sample_job["jid"]: {
                **sample_job,
                "finished": False,
                "rc": None,
            }
        }
        with open(tmp_jobs_file, "w") as f:
            json.dump(jobs_data, f)

        try:
            from async_registry import AsyncRegistry
            with patch("os.kill", return_value=None):
                registry = AsyncRegistry(jobs_file=tmp_jobs_file)
                registry.restore_on_restart()

            job = registry.get_job(sample_job["jid"])
            assert job["finished"] is False
            assert job["rc"] is None
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.restore_on_restart non implémenté — test ignoré")

    def test_already_finished_job_on_restart_unchanged(self, tmp_jobs_file, sample_job):
        """Au redémarrage, job déjà terminé → non modifié."""
        jobs_data = {
            sample_job["jid"]: {
                **sample_job,
                "finished": True,
                "rc": 0,
            }
        }
        with open(tmp_jobs_file, "w") as f:
            json.dump(jobs_data, f)

        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.restore_on_restart()

            job = registry.get_job(sample_job["jid"])
            assert job["finished"] is True
            assert job["rc"] == 0
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.restore_on_restart non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests timeout des jobs async
# ---------------------------------------------------------------------------

class TestAsyncJobTimeout:
    """Tests du timeout des tâches async longues."""

    def test_expired_timeout_kills_process(self, tmp_jobs_file):
        """Job dont async_timeout est dépassé → SIGTERM envoyé, rc=-15."""
        expired_job = {
            "jid": "jid-expired",
            "pid": 12345,
            "cmd": "./long_task.sh",
            "started_at": time.time() - 4000,  # commencé il y a 4000s
            "timeout": 3600,  # timeout à 3600s
            "stdout_path": "/tmp/jid-expired.stdout",
            "finished": False,
            "rc": None,
        }

        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=expired_job["jid"],
                pid=expired_job["pid"],
                cmd=expired_job["cmd"],
                timeout=expired_job["timeout"],
                stdout_path=expired_job["stdout_path"],
            )
            # Forcer started_at dans le passé
            registry._jobs[expired_job["jid"]]["started_at"] = expired_job["started_at"]

            kill_calls = []
            with patch("os.kill", side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
                registry.check_and_kill_expired()

            assert len(kill_calls) >= 1
            killed_pid, killed_sig = kill_calls[0]
            assert killed_pid == expired_job["pid"]
            import signal
            assert killed_sig == signal.SIGTERM
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.check_and_kill_expired non implémenté — test ignoré")

    def test_expired_timeout_marks_job_killed(self, tmp_jobs_file):
        """Après kill, job marqué finished=True, rc=-15."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid="jid-kill-test",
                pid=12345,
                cmd="./slow.sh",
                timeout=3600,
                stdout_path="/tmp/jid-kill-test.stdout",
            )
            registry._jobs["jid-kill-test"]["started_at"] = time.time() - 4000

            with patch("os.kill"):
                registry.check_and_kill_expired()

            job = registry.get_job("jid-kill-test")
            assert job["finished"] is True
            assert job["rc"] == -15
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.check_and_kill_expired non implémenté — test ignoré")

    def test_non_expired_job_not_killed(self, tmp_jobs_file):
        """Job dans les délais → aucun SIGTERM envoyé."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid="jid-ok",
                pid=12345,
                cmd="./fast.sh",
                timeout=3600,
                stdout_path="/tmp/jid-ok.stdout",
            )
            # started_at récent → pas expiré
            registry._jobs["jid-ok"]["started_at"] = time.time() - 60

            kill_calls = []
            with patch("os.kill", side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
                registry.check_and_kill_expired()

            assert len(kill_calls) == 0
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.check_and_kill_expired non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests async_status (poll)
# ---------------------------------------------------------------------------

class TestAsyncStatus:
    """Tests de la vérification du statut d'un job async (async_status)."""

    def test_running_job_returns_finished_zero(self, tmp_jobs_file, sample_job):
        """Job en cours → réponse avec finished=0."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )

            with patch("os.kill", return_value=None):  # PID vivant
                status = registry.get_async_status(sample_job["jid"])

            assert status["ansible_job_id"] == sample_job["jid"]
            assert status["finished"] == 0
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.get_async_status non implémenté — test ignoré")

    def test_finished_job_returns_finished_one_with_rc(self, tmp_jobs_file, sample_job):
        """Job terminé → réponse avec finished=1 et rc."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            # Marquer comme terminé
            registry._jobs[sample_job["jid"]]["finished"] = True
            registry._jobs[sample_job["jid"]]["rc"] = 0

            status = registry.get_async_status(sample_job["jid"])
            assert status["finished"] == 1
            assert status["rc"] == 0
            assert status["ansible_job_id"] == sample_job["jid"]
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.get_async_status non implémenté — test ignoré")

    def test_unknown_jid_returns_error(self, tmp_jobs_file):
        """jid inconnu → statut avec erreur."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            status = registry.get_async_status("nonexistent-jid")
            assert status.get("failed") is True or status.get("rc", 0) != 0 or "error" in status
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.get_async_status non implémenté — test ignoré")

    def test_finished_job_includes_stdout(self, tmp_jobs_file, sample_job, tmp_path):
        """Job terminé → stdout inclus dans le statut."""
        stdout_file = tmp_path / "stdout.txt"
        stdout_content = "task completed successfully\n"
        stdout_file.write_text(stdout_content)

        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=str(stdout_file),
            )
            registry._jobs[sample_job["jid"]]["finished"] = True
            registry._jobs[sample_job["jid"]]["rc"] = 0

            status = registry.get_async_status(sample_job["jid"])
            assert "stdout" in status
            assert stdout_content in status["stdout"]
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.get_async_status non implémenté — test ignoré")


# ---------------------------------------------------------------------------
# Tests sauvegarde persistante après update
# ---------------------------------------------------------------------------

class TestPersistence:
    """Tests de la persistance des mises à jour sur disque."""

    def test_update_job_persists(self, tmp_jobs_file, sample_job):
        """Après update d'un job, les changements sont écrits sur disque."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            registry.update_job(sample_job["jid"], finished=True, rc=0)

            # Charger depuis disque et vérifier
            with open(tmp_jobs_file) as f:
                data = json.load(f)
            assert data[sample_job["jid"]]["finished"] is True
            assert data[sample_job["jid"]]["rc"] == 0
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.update_job non implémenté — test ignoré")

    def test_remove_job_persists(self, tmp_jobs_file, sample_job):
        """Après suppression d'un job, il n'est plus dans le fichier."""
        try:
            from async_registry import AsyncRegistry
            registry = AsyncRegistry(jobs_file=tmp_jobs_file)
            registry.register_job(
                jid=sample_job["jid"],
                pid=sample_job["pid"],
                cmd=sample_job["cmd"],
                timeout=sample_job["timeout"],
                stdout_path=sample_job["stdout_path"],
            )
            registry.remove_job(sample_job["jid"])

            with open(tmp_jobs_file) as f:
                data = json.load(f)
            assert sample_job["jid"] not in data
        except (ImportError, AttributeError):
            pytest.skip("async_registry.AsyncRegistry.remove_job non implémenté — test ignoré")
