"""
main.py — Orchestrateur principal du système de détection ransomware

Point d'entrée unique. Lance tous les modules dans le bon ordre :
  1. Initialisation du logger
  2. Chargement / entraînement du modèle ML
  3. Déploiement des canary files
  4. Démarrage de la surveillance Watchdog
  5. Boucle principale avec gestion des alertes
"""

import sys
import time
import signal
import logging
import argparse
from pathlib import Path

# ── Ajout du répertoire projet au path ──────────────────────
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "analysis"))
sys.path.insert(0, str(Path(__file__).parent / "canary"))
sys.path.insert(0, str(Path(__file__).parent / "monitor"))
sys.path.insert(0, str(Path(__file__).parent / "response"))

from config import (
    CANARY_DIRS, CANARY_COUNT, MODEL_PATH,
    ENTROPY_CRITICAL, ENTROPY_DELTA_ALERT, AUTO_KILL
)
from canary.canary_manager import CanaryManager
from analysis.entropy      import entropy_report
from analysis.features     import FeatureExtractor
from analysis.ml_model     import RansomwareDetector
from monitor.watcher       import FileSystemWatcher
from response.killer       import respond_to_threat
from response.alerting     import AlertManager, AlertLevel, setup_logger


# ──────────────────────────────────────────────────────────────
#  ORCHESTRATEUR
# ──────────────────────────────────────────────────────────────

class RansomwareDetectionSystem:
    """
    Système complet de détection précoce de ransomware.

    Intègre tous les modules dans une architecture événementielle :
      CanaryManager → FileSystemWatcher → FeatureExtractor
           → RansomwareDetector → AlertManager → Killer
    """

    def __init__(self, train_model: bool = False):
        self.logger    = setup_logger()
        self.alert_mgr = AlertManager()
        self.canary    = CanaryManager(CANARY_DIRS, CANARY_COUNT)
        self.extractor = FeatureExtractor()
        self.detector  = RansomwareDetector()
        self.watcher   = None
        self._running  = False

        self._init_model(train_model)

    # ──────────────────────────────
    #  INITIALISATION
    # ──────────────────────────────

    def _init_model(self, force_train: bool) -> None:
        """Charge le modèle ML existant ou en entraîne un nouveau."""
        if not force_train and self.detector.load(MODEL_PATH):
            self.logger.info("🧠 Modèle ML chargé depuis le disque.")
        else:
            self.logger.info("🏋️  Entraînement du modèle ML (première fois)…")
            metrics = self.detector.train(verbose=True)
            self.detector.save(MODEL_PATH)
            self.logger.info(
                f"✅ Modèle entraîné — F1={metrics['f1']:.1%} | "
                f"Recall={metrics['recall']:.1%}"
            )

    # ──────────────────────────────
    #  DÉMARRAGE
    # ──────────────────────────────

    def start(self) -> None:
        """Lance le système complet."""
        self.logger.info("=" * 60)
        self.logger.info("  🛡  RansomwareDetector — Démarrage")
        self.logger.info("=" * 60)

        # Déploiement des canary files
        self.logger.info("🪤 Déploiement des fichiers canary…")
        deployed = self.canary.deploy()
        self.logger.info(f"   ✅ {len(deployed)} canary files déployés.")

        # Configuration du watcher
        self.watcher = FileSystemWatcher(self.canary)
        self.watcher.on_canary_modified   = self._on_canary_event
        self.watcher.on_mass_modification = self._on_mass_event
        self.watcher.on_suspicious_rename = self._on_rename_event

        self.watcher.start()
        self._running = True

        self.logger.info("🔍 Surveillance active. Ctrl+C pour arrêter.\n")

        # Boucle principale
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Arrêt propre : retire les canary, stoppe la surveillance."""
        self.logger.info("\n🛑 Arrêt du système…")
        self._running = False

        if self.watcher:
            self.watcher.stop()

        removed = self.canary.cleanup()
        self.logger.info(f"🗑  {removed} canary files supprimés.")

        total_alerts = self.alert_mgr.critical_count()
        self.logger.info(
            f"📊 Session terminée — {total_alerts} alertes critiques déclenchées."
        )

    # ──────────────────────────────
    #  CALLBACKS ÉVÉNEMENTS
    # ──────────────────────────────

    def _on_canary_event(self, filepath: str, event_type: str) -> None:
        """
        Callback déclenché quand un fichier canary est touché.
        Pipeline : entropie → features → ML → alerte → kill
        """
        baseline = self.canary.get_baseline(filepath)
        report   = entropy_report(filepath, baseline)

        entropy = report["entropy"]
        delta   = report["delta"]

        self.logger.critical(
            f"🚨 CANARY [{event_type}] {Path(filepath).name} | "
            f"Entropie : {entropy:.2f} bits (baseline={baseline:.2f}, Δ={delta:+.2f})"
        )

        # Extraction des features pour le ML
        features = self.extractor.extract(
            entropy_value    = entropy,
            entropy_baseline = baseline,
            filepath         = filepath,
            original_size    = report["file_size"],
        )

        # Prédiction ML
        ml_result = self.detector.predict(features)

        self.logger.warning(
            f"🧠 ML : {ml_result['label']} | "
            f"Confiance : {ml_result['confidence']:.0%} | "
            f"Niveau : {ml_result['threat_level']}/5\n"
            f"   → {ml_result['explanation']}"
        )

        # Alerte
        self.alert_mgr.alert_canary_compromised(
            filepath, entropy, delta, ml_result
        )

        # Réponse automatique si menace confirmée
        if AUTO_KILL and (
            report["suspicious"]
            or ml_result["label"] == "RANSOMWARE"
            or ml_result["threat_level"] >= 3
        ):
            self.logger.critical("⚡ RÉPONSE AUTOMATIQUE DÉCLENCHÉE")
            response = respond_to_threat(filepath, ml_result)
            self.logger.critical(
                f"🔪 {response['processes_killed']}/"
                f"{response['processes_found']} processus neutralisés."
            )

    def _on_mass_event(self, count: int, rate: float) -> None:
        """Callback pour détection de chiffrement de masse."""
        self.alert_mgr.alert_mass_encryption(count, rate)
        self.extractor.record_modification()

    def _on_rename_event(self, src: str, dst: str, ext: str) -> None:
        """Callback pour détection d'extension ransomware."""
        self.alert_mgr.alert_suspicious_rename(src, dst, ext)
        self.extractor.record_rename()


# ──────────────────────────────────────────────────────────────
#  POINT D'ENTRÉE CLI
# ──────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="🛡  Système de détection précoce de ransomware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python main.py                  # Démarrage normal
  python main.py --train          # Forcer le ré-entraînement du modèle
  python main.py --status         # Afficher l'état des canary files
  python main.py --cleanup        # Supprimer tous les canary files
        """
    )
    parser.add_argument(
        "--train",   action="store_true",
        help="Forcer le ré-entraînement du modèle ML"
    )
    parser.add_argument(
        "--status",  action="store_true",
        help="Afficher l'état des canary files et quitter"
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Supprimer tous les canary files et quitter"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.status:
        mgr = CanaryManager()
        if mgr.load_state():
            report = mgr.status_report()
            print(f"\n{'='*50}")
            print(f"  Canary Files — Statut ({report['total_deployed']} fichiers)")
            print(f"{'='*50}")
            for f in report["files"]:
                status = "✅ SAFE" if f["exists"] else "❌ MANQUANT"
                curr   = f["current_entropy"]
                base   = f["baseline"]
                delta  = curr - base if curr > 0 and base > 0 else 0
                print(
                    f"  {status}  {Path(f['path']).name:<40} "
                    f"H={curr:.2f} (Δ{delta:+.2f})"
                )
        else:
            print("⚠️  Aucun état canary trouvé. Lancer main.py d'abord.")
        return

    if args.cleanup:
        mgr = CanaryManager()
        if mgr.load_state():
            n = mgr.cleanup()
            print(f"✅ {n} canary files supprimés.")
        else:
            print("Aucun état à nettoyer.")
        return

    # Démarrage normal
    system = RansomwareDetectionSystem(train_model=args.train)

    # Gestion du signal SIGINT proprement
    def _handle_signal(sig, frame):
        system.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    system.start()


if __name__ == "__main__":
    main()
