"""
analysis/entropy.py — Calcul de l'entropie de Shannon sur les fichiers

L'entropie mesure le degré d'aléatoire des données (0 à 8 bits) :
  - Fichier texte normal   → ~3.5 bits
  - Fichier compressé      → ~6.5 bits
  - Fichier chiffré (AES)  → ~7.9 bits  ← signature ransomware
"""

import math
from collections import Counter
from pathlib import Path
from typing import Tuple

from config import CHUNK_SIZE, ENTROPY_WARNING, ENTROPY_CRITICAL


# ──────────────────────────────────────────────────────────────
#  CALCUL PRINCIPAL
# ──────────────────────────────────────────────────────────────

def calculate_entropy(filepath: str | Path, chunk_size: int = CHUNK_SIZE) -> float:
    """
    Calcule l'entropie de Shannon d'un fichier en bits (0.0 – 8.0).

    Lecture par chunks pour supporter les gros fichiers sans saturer la RAM.
    Formule : H = -Σ p(x) * log2(p(x))  où p(x) = fréquence de l'octet x.

    Args:
        filepath:   Chemin vers le fichier à analyser.
        chunk_size: Taille des chunks de lecture en octets.

    Returns:
        Entropie en bits, arrondie à 4 décimales.
        Retourne -1.0 en cas d'erreur (fichier inaccessible, vide…).
    """
    try:
        filepath = Path(filepath)
        if not filepath.exists() or not filepath.is_file():
            return -1.0

        counts: Counter = Counter()
        total_bytes: int = 0

        with filepath.open("rb") as fh:
            while chunk := fh.read(chunk_size):
                counts.update(chunk)
                total_bytes += len(chunk)

        if total_bytes == 0:
            return 0.0

        entropy: float = 0.0
        for count in counts.values():
            p = count / total_bytes
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (OSError, PermissionError):
        return -1.0


def calculate_entropy_bytes(data: bytes) -> float:
    """
    Calcule l'entropie directement sur un buffer mémoire (bytes).
    Utile pour les tests unitaires ou l'analyse en mémoire.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return round(entropy, 4)


# ──────────────────────────────────────────────────────────────
#  CLASSIFICATION & DELTA
# ──────────────────────────────────────────────────────────────

def classify_entropy(value: float) -> str:
    """
    Classifie une valeur d'entropie en catégorie lisible.

    Returns:
        "ERROR"    → fichier inaccessible (value == -1.0)
        "NORMAL"   → activité bureautique normale (< 6.0)
        "WARNING"  → compressé ou partiellement chiffré (6.0–7.2)
        "CRITICAL" → chiffré / ransomware probable (> 7.2)
    """
    if value < 0:
        return "ERROR"
    if value < ENTROPY_WARNING:
        return "NORMAL"
    if value < ENTROPY_CRITICAL:
        return "WARNING"
    return "CRITICAL"


def get_entropy_delta(baseline: float, current: float) -> float:
    """
    Calcule la variation absolue d'entropie entre deux mesures.

    Args:
        baseline: Entropie enregistrée au déploiement du canary.
        current:  Entropie mesurée après modification.

    Returns:
        Delta positif si l'entropie a augmenté (mauvais signe).
    """
    if baseline < 0 or current < 0:
        return 0.0
    return round(current - baseline, 4)


def is_suspicious(
    current_entropy: float,
    baseline_entropy: float = 0.0,
    entropy_threshold: float = ENTROPY_CRITICAL,
    delta_threshold: float = 1.5,
) -> Tuple[bool, str]:
    """
    Détermine si un fichier est suspect selon son entropie.

    Deux critères indépendants déclenchent une alerte :
      1. Entropie absolue dépasse le seuil critique (> 7.2 par défaut)
      2. Delta brutal par rapport à la baseline (> 1.5 bits par défaut)

    Returns:
        (True, raison) si suspect, (False, "") sinon.
    """
    delta = get_entropy_delta(baseline_entropy, current_entropy)

    if current_entropy >= entropy_threshold:
        return True, f"Entropie critique ({current_entropy:.2f} bits ≥ {entropy_threshold})"

    if abs(delta) >= delta_threshold and baseline_entropy > 0:
        return True, f"Delta brutal (+{delta:.2f} bits vs baseline {baseline_entropy:.2f})"

    return False, ""


# ──────────────────────────────────────────────────────────────
#  RAPPORT FORMATÉ
# ──────────────────────────────────────────────────────────────

def entropy_report(filepath: str | Path, baseline: float = 0.0) -> dict:
    """
    Génère un rapport complet d'analyse entropique pour un fichier.

    Returns:
        dict avec toutes les métriques utiles pour le modèle ML et les logs.
    """
    filepath = Path(filepath)
    current  = calculate_entropy(filepath)
    delta    = get_entropy_delta(baseline, current)
    status   = classify_entropy(current)
    suspicious, reason = is_suspicious(current, baseline)

    return {
        "filepath":    str(filepath),
        "filename":    filepath.name,
        "entropy":     current,
        "baseline":    baseline,
        "delta":       delta,
        "status":      status,
        "suspicious":  suspicious,
        "reason":      reason,
        "file_size":   filepath.stat().st_size if filepath.exists() else 0,
    }
