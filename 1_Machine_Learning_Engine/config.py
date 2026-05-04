"""
config.py — Configuration centralisée du système de détection ransomware
"""

from pathlib import Path
import platform

BASE_DIR = Path(__file__).parent

# ─────────────────────────────────────────────
#  CANARY FILES
# ─────────────────────────────────────────────
CANARY_DIRS = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]
if platform.system() == "Windows":
    CANARY_DIRS.append(Path("C:/Users/Public"))
else:
    CANARY_DIRS.append(Path("/tmp"))

CANARY_COUNT       = 20
CANARY_HIDDEN      = True          # Attribut caché sur Windows
CANARY_STATE_FILE  = BASE_DIR / "logs" / "canary_state.json"

# ─────────────────────────────────────────────
#  SEUILS D'ENTROPIE (bits, 0–8)
# ─────────────────────────────────────────────
ENTROPY_NORMAL_MAX   = 6.0   # Fichiers bureautiques normaux
ENTROPY_WARNING      = 6.0   # Début de surveillance accrue
ENTROPY_CRITICAL     = 7.2   # Chiffrement probable → ALERTE
ENTROPY_DELTA_ALERT  = 1.5   # Variation brutale → suspect

# ─────────────────────────────────────────────
#  DÉTECTION DE MASSE
# ─────────────────────────────────────────────
MASS_MOD_THRESHOLD   = 50    # fichiers modifiés/minute → alerte
MASS_MOD_WINDOW_SEC  = 60    # Fenêtre de comptage

# ─────────────────────────────────────────────
#  RÉPONSE AUTOMATIQUE
# ─────────────────────────────────────────────
AUTO_KILL            = True   # Tuer automatiquement le process suspect
AUTO_NETWORK_BLOCK   = False  # Bloquer le réseau (demande confirmation)
QUARANTINE_FIRST     = True   # Suspendre avant de tuer (forensics)

# ─────────────────────────────────────────────
#  MODÈLE ML
# ─────────────────────────────────────────────
MODEL_PATH           = BASE_DIR / "models" / "detector.pkl"
RF_ESTIMATORS        = 200
RF_MAX_DEPTH         = 10
IF_CONTAMINATION     = 0.01   # 1% d'anomalies attendues
THREAT_CONFIDENCE    = 0.70   # Seuil de confiance RF pour déclencher
IF_SCORE_THRESHOLD   = -0.5   # Seuil Isolation Forest

# ─────────────────────────────────────────────
#  ALERTES & NOTIFICATIONS
# ─────────────────────────────────────────────
ALERT_EMAIL_ENABLED  = False
ALERT_EMAIL_TO       = ""
ALERT_SMTP_HOST      = "smtp.gmail.com"
ALERT_SMTP_PORT      = 587
ALERT_SMTP_USER      = ""
ALERT_SMTP_PASS      = ""

WEBHOOK_ENABLED      = False
WEBHOOK_URL          = ""     # Slack / Teams / Discord

# ─────────────────────────────────────────────
#  LOGS & FORENSICS
# ─────────────────────────────────────────────
LOG_DIR              = BASE_DIR / "logs"
FORENSICS_LOG        = LOG_DIR / "forensics.json"
APP_LOG              = LOG_DIR / "app.log"
LOG_LEVEL            = "DEBUG"   # DEBUG | INFO | WARNING | CRITICAL

# ─────────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────────
DASHBOARD_HOST       = "127.0.0.1"
DASHBOARD_PORT       = 5000
DASHBOARD_DEBUG      = False

# ─────────────────────────────────────────────
#  PERFORMANCE
# ─────────────────────────────────────────────
CHUNK_SIZE           = 65536   # 64KB — lecture fichier par chunks
WATCHER_TIMEOUT      = 1.0     # secondes entre chaque poll Watchdog
MAX_WORKER_THREADS   = 4       # Threads d'analyse parallèles
