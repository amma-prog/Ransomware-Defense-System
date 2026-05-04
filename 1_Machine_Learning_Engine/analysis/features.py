"""
analysis/features.py — Extraction du vecteur de features comportementales

Chaque événement suspect est transformé en un vecteur numérique
utilisé par le modèle ML pour classifier la menace.
"""

import time
import platform
from collections import deque
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Optional

import psutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MASS_MOD_WINDOW_SEC


# ──────────────────────────────────────────────────────────────
#  FENÊTRE GLISSANTE — comptage des événements récents
# ──────────────────────────────────────────────────────────────

class SlidingWindowCounter:
    """
    Compteur thread-safe à fenêtre glissante temporelle.
    Utilisé pour mesurer la cadence des modifications (fichiers/sec).
    """

    def __init__(self, window_seconds: int = MASS_MOD_WINDOW_SEC):
        self.window   = window_seconds
        self._events  = deque()
        self._lock    = Lock()

    def record(self) -> None:
        """Enregistre un nouvel événement avec le timestamp courant."""
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            self._purge(now)

    def count(self) -> int:
        """Retourne le nombre d'événements dans la fenêtre courante."""
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            return len(self._events)

    def rate_per_second(self) -> float:
        """Retourne la cadence moyenne en événements/seconde."""
        n = self.count()
        return round(n / self.window, 4) if self.window > 0 else 0.0

    def _purge(self, now: float) -> None:
        """Supprime les événements trop anciens (hors fenêtre)."""
        cutoff = now - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


# ──────────────────────────────────────────────────────────────
#  RÉPUTATION DES PROCESSUS
# ──────────────────────────────────────────────────────────────

TRUSTED_PROCESSES = {
    # Windows
    "explorer.exe", "svchost.exe", "system", "winword.exe",
    "excel.exe", "powerpnt.exe", "outlook.exe", "msedge.exe",
    "chrome.exe", "firefox.exe", "code.exe", "notepad.exe",
    # Linux / macOS
    "bash", "zsh", "python3", "python", "vim", "nano",
    "gedit", "code", "firefox", "chromium",
}

SUSPICIOUS_PROCESS_NAMES = {
    # Patterns connus de ransomwares (noms de binaires génériques)
    "vssadmin.exe",    # Suppression des shadow copies
    "bcdedit.exe",     # Modification du boot
    "wbadmin.exe",     # Suppression des backups
    "cipher.exe",      # Chiffrement Windows
    "schtasks.exe",    # Planification de tâches (persistance)
    "powershell.exe",  # Souvent utilisé pour dropper
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


def get_process_reputation(pid: Optional[int]) -> float:
    """
    Évalue la réputation d'un processus (0.0 = suspect, 1.0 = fiable).

    Critères :
      - Processus dans la liste de confiance → 1.0
      - Processus signé + chemin système → 0.8
      - Processus dans liste suspecte → 0.0
      - Inconnu → 0.5

    Args:
        pid: PID du processus à évaluer. None → 0.5

    Returns:
        Score de réputation entre 0.0 et 1.0.
    """
    if pid is None:
        return 0.5
    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()

        if name in SUSPICIOUS_PROCESS_NAMES:
            return 0.0
        if name in TRUSTED_PROCESSES:
            return 1.0

        # Vérification du chemin (processus système vs user)
        exe = proc.exe().lower() if proc.exe() else ""
        if platform.system() == "Windows":
            if "system32" in exe or "program files" in exe:
                return 0.8
        else:
            if exe.startswith("/usr/") or exe.startswith("/bin/"):
                return 0.8

        return 0.5

    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return 0.5


# ──────────────────────────────────────────────────────────────
#  EXTRACTEUR DE FEATURES
# ──────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extrait un vecteur de 9 features numériques à partir
    des événements filesystem et des informations système.

    Features extraites :
      0. entropy_value       — Entropie actuelle du fichier (0–8)
      1. entropy_delta       — Variation vs baseline
      2. modification_rate   — Fichiers modifiés/seconde (fenêtre 60s)
      3. extension_changed   — Extension différente de l'original (0/1)
      4. size_ratio          — Taille_new / Taille_originale
      5. time_of_day         — Heure (0–23), activité nocturne = suspect
      6. process_reputation  — Score de confiance du process (0–1)
      7. files_renamed_count — Renommages dans les 60 dernières secondes
      8. shadow_copy_access  — Tentative d'accès VSS détectée (0/1)
    """

    FEATURE_NAMES = [
        "entropy_value",
        "entropy_delta",
        "modification_rate",
        "extension_changed",
        "size_ratio",
        "time_of_day",
        "process_reputation",
        "files_renamed_count",
        "shadow_copy_access",
    ]

    def __init__(self):
        self._mod_counter    = SlidingWindowCounter(MASS_MOD_WINDOW_SEC)
        self._rename_counter = SlidingWindowCounter(MASS_MOD_WINDOW_SEC)
        self._vss_detected   = False

    # ──────────────────────────────
    #  MISE À JOUR DES COMPTEURS
    # ──────────────────────────────

    def record_modification(self) -> None:
        """À appeler à chaque événement de modification détecté."""
        self._mod_counter.record()

    def record_rename(self) -> None:
        """À appeler à chaque événement de renommage détecté."""
        self._rename_counter.record()

    def signal_vss_access(self) -> None:
        """Marque une tentative d'accès aux shadow copies."""
        self._vss_detected = True

    # ──────────────────────────────
    #  EXTRACTION
    # ──────────────────────────────

    def extract(
        self,
        entropy_value:    float,
        entropy_baseline: float,
        filepath:         str | Path,
        original_size:    int,
        pid:              Optional[int] = None,
    ) -> dict:
        """
        Construit le vecteur de features pour un événement donné.

        Args:
            entropy_value:    Entropie mesurée après modification.
            entropy_baseline: Entropie enregistrée au déploiement.
            filepath:         Chemin du fichier modifié.
            original_size:    Taille originale en octets (baseline).
            pid:              PID du processus responsable (optionnel).

        Returns:
            dict {feature_name: valeur_numérique}
        """
        filepath = Path(filepath)

        # Feature 0 — Entropie absolue
        f_entropy = max(0.0, float(entropy_value))

        # Feature 1 — Delta d'entropie
        f_delta = max(0.0, entropy_value - entropy_baseline) if entropy_baseline >= 0 else 0.0

        # Feature 2 — Cadence de modification
        self.record_modification()
        f_rate = self._mod_counter.rate_per_second()

        # Feature 3 — Extension changée ?
        original_ext = filepath.suffix.lower()
        current_ext  = filepath.suffix.lower()
        f_ext_changed = 0.0  # Watchdog ne fournit pas l'ancien nom ici
        # À surcharger si on détecte un rename précédent

        # Feature 4 — Ratio de taille
        try:
            current_size = filepath.stat().st_size if filepath.exists() else 0
            f_size_ratio = (current_size / original_size) if original_size > 0 else 1.0
            f_size_ratio = round(min(f_size_ratio, 10.0), 4)  # Cap à 10x
        except OSError:
            f_size_ratio = 1.0

        # Feature 5 — Heure de la journée
        f_time = float(datetime.now().hour)

        # Feature 6 — Réputation du processus
        f_reputation = get_process_reputation(pid)

        # Feature 7 — Nombre de renommages récents
        f_renames = float(self._rename_counter.count())

        # Feature 8 — Accès shadow copies
        f_vss = 1.0 if self._vss_detected else 0.0

        return {
            "entropy_value":       f_entropy,
            "entropy_delta":       f_delta,
            "modification_rate":   f_rate,
            "extension_changed":   f_ext_changed,
            "size_ratio":          f_size_ratio,
            "time_of_day":         f_time,
            "process_reputation":  f_reputation,
            "files_renamed_count": f_renames,
            "shadow_copy_access":  f_vss,
        }

    def to_vector(self, features_dict: dict) -> list[float]:
        """
        Convertit le dict de features en liste ordonnée pour le modèle ML.
        L'ordre correspond à FEATURE_NAMES.
        """
        return [float(features_dict.get(k, 0.0)) for k in self.FEATURE_NAMES]

    def reset_vss_flag(self) -> None:
        """Réinitialise le flag VSS après traitement."""
        self._vss_detected = False
