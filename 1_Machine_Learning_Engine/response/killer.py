"""
response/killer.py — Identification et neutralisation des processus suspects

Stratégie de réponse incidente :
  1. Identifier le(s) processus qui accèdent au fichier canary
  2. Prendre un snapshot forensique complet
  3. Suspendre le processus (quarantaine)
  4. Tuer le processus après confirmation
  5. Logger toutes les actions en JSON immuable
"""

import sys
import json
import time
import platform
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import QUARANTINE_FIRST, AUTO_NETWORK_BLOCK, FORENSICS_LOG

logger = logging.getLogger("RansomwareDetector.Killer")


# ──────────────────────────────────────────────────────────────
#  SNAPSHOT FORENSIQUE
# ──────────────────────────────────────────────────────────────

def take_process_snapshot(proc: psutil.Process) -> dict:
    """
    Capture toutes les informations disponibles sur un processus
    avant de le neutraliser (pour analyse post-mortem).

    Returns:
        dict complet avec pid, nom, cmdline, fichiers ouverts,
        connexions réseau, etc.
    """
    snapshot = {
        "timestamp":   datetime.now().isoformat(),
        "pid":         proc.pid,
        "name":        "UNKNOWN",
        "exe":         "UNKNOWN",
        "cmdline":     [],
        "ppid":        None,
        "parent_name": None,
        "username":    "UNKNOWN",
        "create_time": None,
        "open_files":  [],
        "connections": [],
        "children":    [],
    }
    try:
        snapshot["name"]        = proc.name()
        snapshot["exe"]         = proc.exe()
        snapshot["cmdline"]     = proc.cmdline()
        snapshot["ppid"]        = proc.ppid()
        snapshot["username"]    = proc.username()
        snapshot["create_time"] = datetime.fromtimestamp(
            proc.create_time()
        ).isoformat()

        # Processus parent
        try:
            parent = psutil.Process(proc.ppid())
            snapshot["parent_name"] = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Fichiers ouverts
        snapshot["open_files"] = [
            f.path for f in proc.open_files()
        ]

        # Connexions réseau actives
        snapshot["connections"] = [
            {
                "fd":     c.fd,
                "family": str(c.family),
                "type":   str(c.type),
                "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status,
            }
            for c in proc.connections(kind="inet")
        ]

        # Processus enfants
        snapshot["children"] = [
            {"pid": c.pid, "name": c.name()}
            for c in proc.children(recursive=True)
        ]

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return snapshot


# ──────────────────────────────────────────────────────────────
#  IDENTIFICATION DES PROCESSUS SUSPECTS
# ──────────────────────────────────────────────────────────────

def get_file_processes(filepath: str) -> list[psutil.Process]:
    """
    Retourne la liste des processus qui ont le fichier ouvert.

    Args:
        filepath: Chemin absolu du fichier à vérifier.

    Returns:
        Liste de psutil.Process (peut être vide).
    """
    suspects = []
    target   = str(Path(filepath).resolve())

    for proc in psutil.process_iter(["pid", "name", "open_files"]):
        try:
            for f in (proc.info.get("open_files") or []):
                if f.path == target:
                    suspects.append(proc)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspects


def find_high_entropy_writers(
    entropy_threshold: float = 7.0,
    rate_threshold: float = 0.3,
) -> list[psutil.Process]:
    """
    Identifie les processus qui écrivent intensivement sur disque,
    caractéristique d'un chiffrement en masse.

    Returns:
        Processus avec I/O write rate anormalement élevé.
    """
    suspicious = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            io1 = proc.io_counters()
            time.sleep(0.1)
            io2 = proc.io_counters()
            write_rate = (io2.write_bytes - io1.write_bytes) / 0.1  # bytes/sec

            # > 5MB/s en écriture = suspect
            if write_rate > 5 * 1024 * 1024:
                suspicious.append(proc)
                logger.warning(
                    f"⚠️  Écriture intensive : {proc.name()} "
                    f"(PID={proc.pid}, {write_rate/1e6:.1f} MB/s)"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious


# ──────────────────────────────────────────────────────────────
#  NEUTRALISATION
# ──────────────────────────────────────────────────────────────

def quarantine_process(proc: psutil.Process) -> bool:
    """
    Suspend le processus (sans le tuer) pour investigation.
    Donne le temps de capturer un snapshot avant suppression.

    Returns:
        True si suspendu avec succès.
    """
    try:
        proc.suspend()
        logger.warning(
            f"⏸  Processus suspendu : {proc.name()} (PID={proc.pid})"
        )
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        logger.error(f"Échec suspension PID {proc.pid} : {e}")
        return False


def kill_process(proc: psutil.Process) -> bool:
    """
    Tue un processus de façon définitive.
    Tente d'abord terminate() (SIGTERM), puis kill() (SIGKILL).

    Returns:
        True si le processus a été tué avec succès.
    """
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
            logger.warning(
                f"🔪 Processus terminé : {proc.name()} (PID={proc.pid})"
            )
            return True
        except psutil.TimeoutExpired:
            proc.kill()
            logger.warning(
                f"💀 Processus tué (SIGKILL) : {proc.name()} (PID={proc.pid})"
            )
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error(f"Impossible de tuer PID {proc.pid} : {e}")
        return False


def block_process_network(pid: int) -> bool:
    """
    Bloque les connexions réseau sortantes du processus.
    Windows : règle de pare-feu netsh
    Linux   : iptables owner match

    Returns:
        True si le blocage a réussi.
    """
    if not AUTO_NETWORK_BLOCK:
        return False

    try:
        if platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=BLOCK_PID_{pid}",
                "dir=out", "action=block",
                f"program={psutil.Process(pid).exe()}"
            ], check=False, capture_output=True)
        else:
            subprocess.run([
                "iptables", "-A", "OUTPUT",
                "-m", "owner", "--pid-owner", str(pid),
                "-j", "DROP"
            ], check=False, capture_output=True)
        return True
    except Exception as e:
        logger.error(f"Blocage réseau échoué (PID={pid}) : {e}")
        return False


# ──────────────────────────────────────────────────────────────
#  RÉPONSE COMPLÈTE
# ──────────────────────────────────────────────────────────────

def respond_to_threat(
    filepath: str,
    alert_data: Optional[dict] = None,
) -> dict:
    """
    Pipeline complet de réponse incidente :
      1. Trouver les processus suspects
      2. Snapshot forensique
      3. Quarantaine (suspend)
      4. Kill
      5. Blocage réseau (optionnel)
      6. Log JSON

    Args:
        filepath:   Fichier canary compromis.
        alert_data: Données supplémentaires d'alerte (entropie, ML…)

    Returns:
        Rapport de réponse complet.
    """
    report = {
        "timestamp":   datetime.now().isoformat(),
        "trigger_file": filepath,
        "processes_found": 0,
        "processes_killed": 0,
        "actions":     [],
        "snapshots":   [],
        "alert_data":  alert_data or {},
    }

    suspects = get_file_processes(filepath)

    if not suspects:
        logger.warning(
            f"Aucun processus trouvé avec {filepath} ouvert. "
            "Peut-être déjà fermé."
        )
        report["actions"].append("NO_PROCESS_FOUND")
        _save_forensic_log(report)
        return report

    report["processes_found"] = len(suspects)

    for proc in suspects:
        # Snapshot avant toute action
        snapshot = take_process_snapshot(proc)
        report["snapshots"].append(snapshot)

        # Blocage réseau (en premier pour couper l'exfiltration)
        if AUTO_NETWORK_BLOCK:
            blocked = block_process_network(proc.pid)
            if blocked:
                report["actions"].append(f"NETWORK_BLOCKED:{proc.pid}")

        # Quarantaine puis kill
        if QUARANTINE_FIRST:
            if quarantine_process(proc):
                report["actions"].append(f"QUARANTINED:{proc.pid}")
                time.sleep(0.5)  # Délai pour capture mémoire

        if kill_process(proc):
            report["processes_killed"] += 1
            report["actions"].append(f"KILLED:{proc.pid}:{proc.name() if proc.is_running() else 'dead'}")

    _save_forensic_log(report)
    logger.critical(
        f"🛡  Réponse complète : {report['processes_killed']}/"
        f"{report['processes_found']} processus neutralisés."
    )
    return report


def _save_forensic_log(report: dict) -> None:
    """Persiste le rapport de réponse en JSON (append)."""
    try:
        log_path = Path(FORENSICS_LOG)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Lecture de l'historique existant
        existing = []
        if log_path.exists():
            try:
                with log_path.open("r", encoding="utf-8") as fh:
                    existing = json.load(fh)
            except json.JSONDecodeError:
                existing = []

        existing.append(report)

        with log_path.open("w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=2, default=str)

    except Exception as e:
        logger.error(f"Échec sauvegarde log forensique : {e}")
