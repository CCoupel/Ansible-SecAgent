"""
async_registry.py — Registre persisté des tâches Ansible async.

Ansible peut lancer des tâches en mode asynchrone (async + poll).
Ce registre stocke l'état de chaque job async sur disque (JSON) pour
survivre à un redémarrage de l'agent.

Format du fichier JSON :
{
    "<jid>": {
        "jid": str,
        "pid": int,
        "cmd": str,
        "started_at": float,     # timestamp epoch
        "timeout": int,          # secondes
        "stdout_path": str,      # fichier stdout du subprocess
        "finished": bool,
        "rc": int | None
    },
    ...
}
"""

import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("relay_agent.async_registry")

_SENTINEL_RC_ORPHAN: int = -1    # PID mort au redémarrage de l'agent
_SENTINEL_RC_TIMEOUT: int = -15  # Tué par timeout (SIGTERM)


class AsyncRegistry:
    """Registre persisté des tâches Ansible async (mode async + poll).

    Stocke les jobs sur disque pour survivre aux redémarrages du daemon.
    Chaque opération qui modifie l'état du registre est immédiatement
    persistée (write-through).

    Args:
        jobs_file: Chemin du fichier JSON de persistance.
    """

    def __init__(self, jobs_file: str) -> None:
        self._jobs_file = jobs_file
        self._jobs: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistance
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Charge le registre depuis le fichier JSON. Crée un registre vide si absent."""
        if not os.path.exists(self._jobs_file):
            self._jobs = {}
            return
        try:
            with open(self._jobs_file, "r", encoding="utf-8") as fh:
                self._jobs = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Impossible de charger %s : %s — registre vide",
                self._jobs_file,
                exc,
            )
            self._jobs = {}

    def _save(self) -> None:
        """Persiste le registre sur disque (write-through)."""
        path = Path(self._jobs_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self._jobs, fh, indent=2)
            # Remplacement atomique
            os.replace(tmp_path, path)
        except OSError as exc:
            logger.error("Erreur sauvegarde registre %s : %s", self._jobs_file, exc)
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # CRUD jobs
    # ------------------------------------------------------------------

    def register_job(
        self,
        jid: str,
        pid: int,
        cmd: str,
        timeout: int,
        stdout_path: str,
    ) -> None:
        """Enregistre un nouveau job async dans le registre.

        Args:
            jid: Identifiant unique du job Ansible (ansible_job_id).
            pid: PID du subprocess lancé.
            cmd: Commande exécutée (pour référence/debug).
            timeout: Timeout en secondes.
            stdout_path: Chemin du fichier stdout du subprocess.
        """
        self._jobs[jid] = {
            "jid": jid,
            "pid": pid,
            "cmd": cmd,
            "started_at": time.time(),
            "timeout": timeout,
            "stdout_path": stdout_path,
            "finished": False,
            "rc": None,
        }
        self._save()

    def get_job(self, jid: str) -> dict[str, Any] | None:
        """Retourne le job correspondant au jid, ou None s'il est inconnu.

        Args:
            jid: Identifiant du job à récupérer.

        Returns:
            Dictionnaire du job ou None.
        """
        return self._jobs.get(jid)

    def update_job(self, jid: str, **kwargs: Any) -> None:
        """Met à jour les champs d'un job existant et persiste.

        Args:
            jid: Identifiant du job à mettre à jour.
            **kwargs: Champs à modifier (ex: finished=True, rc=0).
        """
        if jid not in self._jobs:
            logger.warning("update_job : jid inconnu %s", jid)
            return
        self._jobs[jid].update(kwargs)
        self._save()

    def remove_job(self, jid: str) -> None:
        """Supprime un job du registre et persiste.

        Args:
            jid: Identifiant du job à supprimer.
        """
        if jid in self._jobs:
            del self._jobs[jid]
            self._save()

    # ------------------------------------------------------------------
    # Vérification de vie d'un PID
    # ------------------------------------------------------------------

    def check_job_alive(self, jid: str) -> bool:
        """Vérifie si le subprocess associé au job est toujours actif.

        Utilise os.kill(pid, 0) : signal 0 ne tue pas le processus,
        il lève ProcessLookupError s'il n'existe pas.

        Args:
            jid: Identifiant du job à vérifier.

        Returns:
            True si le processus est vivant ou inaccessible (PermissionError),
            False si le PID n'existe pas.
        """
        job = self._jobs.get(jid)
        if job is None:
            return False
        pid: int = job["pid"]
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Le processus existe mais on n'a pas les droits de signaler
            return True

    # ------------------------------------------------------------------
    # Reprise après redémarrage
    # ------------------------------------------------------------------

    def restore_on_restart(self) -> None:
        """Réconcilie l'état des jobs au redémarrage de l'agent.

        Pour chaque job non terminé dans le registre :
        - PID mort → marque finished=True, rc=-1
        - PID vivant → conserve l'état en cours (le subprocess tourne encore)
        """
        for jid, job in list(self._jobs.items()):
            if job.get("finished"):
                continue
            pid: int = job["pid"]
            try:
                os.kill(pid, 0)
                # PID vivant — pas de modification
                logger.info(
                    "restore_on_restart : job %s PID %d toujours actif",
                    jid, pid,
                )
            except ProcessLookupError:
                # PID mort : le job est orphelin
                logger.warning(
                    "restore_on_restart : job %s PID %d mort — marqué orphelin",
                    jid, pid,
                )
                self._jobs[jid]["finished"] = True
                self._jobs[jid]["rc"] = _SENTINEL_RC_ORPHAN
            except PermissionError:
                # Processus existant mais inaccessible — conserve l'état
                pass

        self._save()

    # ------------------------------------------------------------------
    # Timeout des jobs async
    # ------------------------------------------------------------------

    def check_and_kill_expired(self) -> None:
        """Envoie SIGTERM aux jobs async dont le timeout est dépassé.

        Pour chaque job non terminé :
        - Si temps écoulé > timeout → SIGTERM + marque finished=True, rc=-15
        """
        now = time.time()
        for jid, job in list(self._jobs.items()):
            if job.get("finished"):
                continue
            elapsed = now - job.get("started_at", now)
            if elapsed > job.get("timeout", 3600):
                pid: int = job["pid"]
                try:
                    os.kill(pid, signal.SIGTERM)
                    logger.warning(
                        "Job async %s (PID %d) tué par timeout (%ds > %ds)",
                        jid, pid, int(elapsed), job["timeout"],
                    )
                except (ProcessLookupError, PermissionError):
                    pass
                self._jobs[jid]["finished"] = True
                self._jobs[jid]["rc"] = _SENTINEL_RC_TIMEOUT

        self._save()

    # ------------------------------------------------------------------
    # async_status (poll Ansible)
    # ------------------------------------------------------------------

    def get_async_status(self, jid: str) -> dict[str, Any]:
        """Retourne le statut d'un job async au format attendu par Ansible.

        Format de réponse (compatible async_status Ansible) :
        - Job en cours  : {"ansible_job_id": jid, "finished": 0, "started": 1}
        - Job terminé   : {"ansible_job_id": jid, "finished": 1, "rc": int,
                           "stdout": str}
        - Job inconnu   : {"ansible_job_id": jid, "failed": True, "rc": -1,
                           "error": "job not found"}

        Args:
            jid: Identifiant du job à interroger.

        Returns:
            Dictionnaire de statut.
        """
        job = self._jobs.get(jid)
        if job is None:
            return {
                "ansible_job_id": jid,
                "failed": True,
                "rc": -1,
                "error": f"job {jid!r} not found in registry",
            }

        if not job.get("finished"):
            return {
                "ansible_job_id": jid,
                "started": 1,
                "finished": 0,
            }

        # Job terminé : lire stdout depuis le fichier
        stdout_content = ""
        stdout_path: str = job.get("stdout_path", "")
        if stdout_path and os.path.exists(stdout_path):
            try:
                with open(stdout_path, "r", encoding="utf-8", errors="replace") as fh:
                    stdout_content = fh.read()
            except OSError as exc:
                logger.warning(
                    "Impossible de lire stdout pour job %s : %s", jid, exc
                )

        return {
            "ansible_job_id": jid,
            "started": 1,
            "finished": 1,
            "rc": job.get("rc"),
            "stdout": stdout_content,
        }
