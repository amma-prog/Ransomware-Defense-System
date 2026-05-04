"""
analysis/ml_model.py — Modèle IA de détection de ransomware

Ensemble de deux algorithmes complémentaires :
  1. Random Forest (supervisé)  → détection basée sur patterns connus
  2. Isolation Forest (non-sup) → détection d'anomalies comportementales

La combinaison couvre à la fois les ransomwares connus ET les zero-days.
"""

import sys
import json
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    MODEL_PATH, RF_ESTIMATORS, RF_MAX_DEPTH,
    IF_CONTAMINATION, THREAT_CONFIDENCE, IF_SCORE_THRESHOLD
)
from analysis.features import FeatureExtractor

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


# ──────────────────────────────────────────────────────────────
#  GÉNÉRATION DU DATASET SYNTHÉTIQUE
# ──────────────────────────────────────────────────────────────

def generate_synthetic_dataset(
    n_normal: int = 10_000,
    n_ransomware: int = 2_000,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Génère un dataset d'entraînement synthétique réaliste.

    Patterns normaux (bureautique) :
      - Entropie faible (3–5.5 bits)
      - Faible cadence de modification
      - Processus reconnus
      - Heures ouvrées

    Patterns ransomware (LockBit / WannaCry / REvil inspired) :
      - Entropie haute (7.0–8.0 bits)
      - Delta brutal (2.0–4.5 bits)
      - Cadence explosive (> 0.5 fichiers/sec)
      - Extensions changées
      - Heures nocturnes ou week-end
      - Réputation process nulle

    Returns:
        (X: features array [n_samples, 9], y: labels array [n_samples])
        Labels: 0 = normal, 1 = ransomware
    """
    rng = np.random.default_rng(random_state)

    # ── Samples normaux ──────────────────────────────────────
    normal = np.column_stack([
        rng.uniform(3.0, 6.8,  n_normal),   # entropy_value (overlap ajouté)
        rng.uniform(0.0, 0.3,  n_normal),   # entropy_delta
        rng.uniform(0.0, 0.05, n_normal),   # modification_rate (lent)
        rng.choice([0, 1], n_normal, p=[0.97, 0.03]),  # extension_changed
        rng.uniform(0.95, 1.05, n_normal),  # size_ratio (~1)
        rng.uniform(8.0, 18.0, n_normal),   # time_of_day (heures bureau)
        rng.uniform(0.7, 1.0,  n_normal),   # process_reputation (élevé)
        rng.integers(0, 3,     n_normal).astype(float),  # renames
        np.zeros(n_normal),                 # shadow_copy_access = 0
    ])
    y_normal = np.zeros(n_normal, dtype=int)

    # ── Faux positifs ambigus (ex: WinRAR, compilation) ──────
    n_ambiguous = n_normal // 10
    ambiguous = np.column_stack([
        rng.uniform(6.5, 7.3, n_ambiguous),  # Entropie haute MAIS normal
        rng.uniform(0.5, 3.5, n_ambiguous),  # Delta parfois très élevé
        rng.uniform(0.1, 1.5, n_ambiguous),  # Rate rapide (comme extraction)
        np.zeros(n_ambiguous),               # Extension pas changée
        rng.uniform(0.9, 1.1, n_ambiguous),  # Size ratio
        rng.uniform(8.0, 18.0, n_ambiguous), # Heures bureau
        rng.uniform(0.7, 1.0, n_ambiguous),  # Process connu
        rng.integers(5, 30, n_ambiguous).astype(float), # Beaucoup de renommages
        np.zeros(n_ambiguous),               # shadow copy = 0
    ])
    y_ambiguous = np.zeros(n_ambiguous, dtype=int)

    # ── Samples ransomware classiques ────────────────────────
    n_rw = n_ransomware
    ransom = np.column_stack([
        rng.uniform(6.2, 8.0,  n_rw),    # entropy_value
        rng.uniform(2.0, 4.5,  n_rw),    # entropy_delta
        rng.uniform(0.3, 2.0,  n_rw),    # modification_rate
        rng.choice([0, 1], n_rw, p=[0.2, 0.8]),   # extension_changed
        rng.uniform(0.9, 1.8,  n_rw),    # size_ratio
        rng.choice(
            list(range(0, 8)) + list(range(22, 24)),
            n_rw
        ).astype(float),                 # time_of_day
        rng.uniform(0.0, 0.3,  n_rw),    # process_reputation
        rng.integers(5, 50,    n_rw).astype(float),  # renames
        rng.choice([0, 1], n_rw, p=[0.4, 0.6]),  # shadow_copy
    ])
    y_ransom = np.ones(n_ransomware, dtype=int)

    # ── Faux négatifs (Ransomware furtifs, lents) ────────────
    n_stealth = n_ransomware // 5
    stealth = np.column_stack([
        rng.uniform(6.5, 7.5, n_stealth),    # Entropie un peu moins grillée
        rng.uniform(0.2, 1.0, n_stealth),    # Delta faible
        rng.uniform(0.02, 0.15, n_stealth),  # Taux très lent!
        rng.choice([0, 1], n_stealth, p=[0.7, 0.3]), # Change pas tjrs l'ext
        rng.uniform(0.95, 1.1, n_stealth),   # Taille presque normale
        rng.uniform(0.0, 24.0, n_stealth),   # N'importe quand
        rng.uniform(0.2, 0.6, n_stealth),    # Fake réputation moyenne
        rng.integers(0, 5, n_stealth).astype(float), # Peu de renames
        np.zeros(n_stealth),                 # Pas de shadow copy kill
    ])
    y_stealth = np.ones(n_stealth, dtype=int)

    X = np.vstack([normal, ambiguous, ransom, stealth])
    y = np.concatenate([y_normal, y_ambiguous, y_ransom, y_stealth])

    # Ajouter bruit global sur toutes les features
    X += rng.normal(0, 0.15, X.shape)
    
    # Clip valeurs pour rester logiques
    X[:, 0] = np.clip(X[:, 0], 0.0, 8.0)  # entropie max = 8.0
    X[:, 1] = np.clip(X[:, 1], 0.0, 8.0)  # delta max = 8.0
    X[:, 2] = np.clip(X[:, 2], 0.0, None) # rate >= 0

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ──────────────────────────────────────────────────────────────
#  DÉTECTEUR PRINCIPAL
# ──────────────────────────────────────────────────────────────

class RansomwareDetector:
    """
    Ensemble Random Forest + Isolation Forest pour la détection ransomware.

    Règle de décision :
      MENACE détectée si :
        RF_probabilité(ransomware) > THREAT_CONFIDENCE (0.70)
        OU
        IF_score < IF_SCORE_THRESHOLD (-0.50)
    """

    THREAT_LEVELS = {
        0: "✅ SAIN",
        1: "⚠️  SUSPECT",
        2: "🟠 MODÉRÉ",
        3: "🔴 ÉLEVÉ",
        4: "🚨 CRITIQUE",
        5: "💀 RANSOMWARE CONFIRMÉ",
    }

    def __init__(self):
        self.rf:      Optional[RandomForestClassifier] = None
        self.iso:     Optional[IsolationForest]        = None
        self.scaler:  Optional[StandardScaler]         = None
        self._trained = False

    # ──────────────────────────────
    #  ENTRAÎNEMENT
    # ──────────────────────────────

    def train(
        self,
        X: Optional[np.ndarray] = None,
        y: Optional[np.ndarray] = None,
        verbose: bool = True,
    ) -> dict:
        """
        Entraîne les deux modèles. Si X/y ne sont pas fournis,
        génère automatiquement un dataset synthétique.

        Returns:
            Rapport de métriques d'évaluation.
        """
        if X is None or y is None:
            if verbose:
                print("📊 Génération du dataset synthétique…")
            X, y = generate_synthetic_dataset()

        # Normalisation
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # ── Random Forest ────────────────────────────────────
        if verbose:
            print(f"🌲 Entraînement Random Forest ({RF_ESTIMATORS} arbres)…")
        self.rf = RandomForestClassifier(
            n_estimators=RF_ESTIMATORS,
            max_depth=RF_MAX_DEPTH,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
        self.rf.fit(X_train, y_train)

        # ── Isolation Forest ─────────────────────────────────
        if verbose:
            print("🔍 Entraînement Isolation Forest…")
        X_normal = X_scaled[y == 0]
        self.iso = IsolationForest(
            contamination=IF_CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self.iso.fit(X_normal)

        self._trained = True

        # ── Évaluation ───────────────────────────────────────
        y_pred   = self.rf.predict(X_test)
        report   = classification_report(y_test, y_pred, output_dict=True)
        cm       = confusion_matrix(y_test, y_pred)

        metrics = {
            "precision":  round(report["1"]["precision"], 4),
            "recall":     round(report["1"]["recall"],    4),
            "f1":         round(report["1"]["f1-score"],  4),
            "accuracy":   round(report["accuracy"],       4),
            "confusion_matrix": cm.tolist(),
            "trained_at": datetime.now().isoformat(),
        }

        if verbose:
            print(f"\n✅ Random Forest — Métriques :")
            print(f"   Précision : {metrics['precision']:.1%}")
            print(f"   Rappel    : {metrics['recall']:.1%}")
            print(f"   F1-Score  : {metrics['f1']:.1%}")
            print(f"   Accuracy  : {metrics['accuracy']:.1%}")

        return metrics

    # ──────────────────────────────
    #  PRÉDICTION
    # ──────────────────────────────

    def predict(self, features: dict) -> dict:
        """
        Prédit si un vecteur de features correspond à une activité ransomware.

        Args:
            features: dict issu de FeatureExtractor.extract()

        Returns:
            {
              "label":        "RANSOMWARE" | "NORMAL",
              "confidence":   float (0–1),
              "threat_level": int (0–5),
              "rf_proba":     float,
              "if_score":     float,
              "explanation":  str,
              "triggered_by": list[str]
            }
        """
        if not self._trained:
            return self._untrained_response()

        # Construire le vecteur dans le bon ordre
        extractor = FeatureExtractor()
        vector    = np.array([extractor.to_vector(features)], dtype=float)
        scaled    = self.scaler.transform(vector)

        # Scores des deux modèles
        rf_proba  = float(self.rf.predict_proba(scaled)[0][1])
        if_score  = float(self.iso.score_samples(scaled)[0])

        # Règle d'ensemble
        triggered_by = []
        if rf_proba > THREAT_CONFIDENCE:
            triggered_by.append(f"RF_proba={rf_proba:.2f}>{THREAT_CONFIDENCE}")
        if if_score < IF_SCORE_THRESHOLD:
            triggered_by.append(f"IF_score={if_score:.2f}<{IF_SCORE_THRESHOLD}")

        is_threat     = bool(triggered_by)
        threat_level  = self._compute_threat_level(rf_proba, if_score, features)
        label         = "RANSOMWARE" if is_threat else "NORMAL"
        explanation   = self._explain(features, rf_proba, if_score, triggered_by)

        return {
            "label":        label,
            "confidence":   round(max(rf_proba, 1 - if_score / 2), 4),
            "threat_level": threat_level,
            "rf_proba":     round(rf_proba, 4),
            "if_score":     round(if_score, 4),
            "explanation":  explanation,
            "triggered_by": triggered_by,
            "features":     features,
        }

    # ──────────────────────────────
    #  PERSISTANCE
    # ──────────────────────────────

    def save(self, path: Path = MODEL_PATH) -> None:
        """Sauvegarde le modèle entraîné sur disque via joblib."""
        if not self._trained:
            raise RuntimeError("Modèle non entraîné. Appeler train() d'abord.")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"rf": self.rf, "iso": self.iso, "scaler": self.scaler},
            path
        )
        print(f"💾 Modèle sauvegardé → {path}")

    def load(self, path: Path = MODEL_PATH) -> bool:
        """
        Charge un modèle pré-entraîné depuis le disque.

        Returns:
            True si chargement réussi, False sinon.
        """
        path = Path(path)
        if not path.exists():
            return False
        try:
            bundle       = joblib.load(path)
            self.rf      = bundle["rf"]
            self.iso     = bundle["iso"]
            self.scaler  = bundle["scaler"]
            self._trained = True
            return True
        except Exception:
            return False

    # ──────────────────────────────
    #  HELPERS PRIVÉS
    # ──────────────────────────────

    def _compute_threat_level(
        self, rf_proba: float, if_score: float, features: dict
    ) -> int:
        """Calcule un niveau de menace de 0 (sain) à 5 (confirmé)."""
        score = 0

        if rf_proba > 0.95:              score += 3
        elif rf_proba > 0.80:            score += 2
        elif rf_proba > THREAT_CONFIDENCE: score += 1

        if if_score < -0.7:              score += 2
        elif if_score < IF_SCORE_THRESHOLD: score += 1

        if features.get("entropy_value", 0) > 7.5:   score += 1
        if features.get("shadow_copy_access", 0) > 0: score += 1
        if features.get("files_renamed_count", 0) > 20: score += 1

        return min(score, 5)

    def _explain(
        self,
        features: dict,
        rf_proba: float,
        if_score: float,
        triggered_by: list[str],
    ) -> str:
        """Génère une explication textuelle lisible de la décision."""
        parts = []

        entropy = features.get("entropy_value", 0)
        if entropy > 7.2:
            parts.append(f"entropie critique ({entropy:.2f} bits)")

        delta = features.get("entropy_delta", 0)
        if delta > 1.5:
            parts.append(f"variation brutale Δ+{delta:.2f} bits")

        rate = features.get("modification_rate", 0)
        if rate > 0.3:
            parts.append(f"cadence de chiffrement élevée ({rate:.1f} fichiers/sec)")

        renames = features.get("files_renamed_count", 0)
        if renames > 10:
            parts.append(f"{int(renames)} renommages en 60s")

        if features.get("shadow_copy_access", 0):
            parts.append("tentative de suppression des shadow copies détectée")

        rep = features.get("process_reputation", 1)
        if rep < 0.3:
            parts.append("processus sans réputation connue")

        if not parts:
            return "Activité dans les normes habituelles."

        return "Signaux suspects : " + " • ".join(parts) + f" (RF={rf_proba:.0%})"

    @staticmethod
    def _untrained_response() -> dict:
        return {
            "label":        "UNKNOWN",
            "confidence":   0.0,
            "threat_level": 0,
            "rf_proba":     0.0,
            "if_score":     0.0,
            "explanation":  "Modèle non initialisé. Appeler train() ou load().",
            "triggered_by": [],
            "features":     {},
        }
