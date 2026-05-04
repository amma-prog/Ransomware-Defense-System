"""
response/alerting.py — Système d'alertes multi-canaux

Niveaux d'alerte :
  INFO      → activité normale surveillée
  WARNING   → anomalie mineure, surveillance accrue
  CRITICAL  → canary compromis → kill déclenché
  EMERGENCY → attaque en masse → isolation réseau
"""

import sys
import json
import smtplib
import logging
import platform
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    APP_LOG, LOG_LEVEL,
    ALERT_EMAIL_ENABLED, ALERT_EMAIL_TO,
    ALERT_SMTP_HOST, ALERT_SMTP_PORT,
    ALERT_SMTP_USER, ALERT_SMTP_PASS,
    WEBHOOK_ENABLED, WEBHOOK_URL,
)


# ──────────────────────────────────────────────────────────────
#  CONFIGURATION DU LOGGER PRINCIPAL
# ──────────────────────────────────────────────────────────────

def setup_logger(name: str = "RansomwareDetector") -> logging.Logger:
    """
    Configure le logger avec handlers console (Rich) et fichier.

    Returns:
        Logger configuré prêt à l'emploi.
    """
    log = logging.getLogger(name)
    log.setLevel(getattr(logging, LOG_LEVEL, logging.DEBUG))

    if log.handlers:
        return log  # Déjà configuré

    # ── Handler console coloré ───────────────────────────────
    try:
        from rich.logging import RichHandler
        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_time=True,
        )
    except ImportError:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
            datefmt="%H:%M:%S"
        ))

    # ── Handler fichier ──────────────────────────────────────
    Path(APP_LOG).parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(APP_LOG, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    ))

    log.addHandler(console_handler)
    log.addHandler(file_handler)
    return log


logger = setup_logger()


# ──────────────────────────────────────────────────────────────
#  NIVEAUX D'ALERTE
# ──────────────────────────────────────────────────────────────

class AlertLevel:
    INFO      = "INFO"
    WARNING   = "WARNING"
    CRITICAL  = "CRITICAL"
    EMERGENCY = "EMERGENCY"

    COLORS = {
        "INFO":      "#00ff88",
        "WARNING":   "#ffaa00",
        "CRITICAL":  "#ff4444",
        "EMERGENCY": "#ff0000",
    }

    EMOJIS = {
        "INFO":      "ℹ️ ",
        "WARNING":   "⚠️ ",
        "CRITICAL":  "🚨",
        "EMERGENCY": "💀",
    }


# ──────────────────────────────────────────────────────────────
#  ALERTEUR PRINCIPAL
# ──────────────────────────────────────────────────────────────

class AlertManager:
    """
    Centralise et dispatche toutes les alertes du système.

    Canaux disponibles :
      - Console (Rich / logging standard)
      - Fichier log
      - Notification OS native (plyer)
      - Email SMTP
      - Webhook HTTP (Slack / Teams / Discord)
    """

    def __init__(self):
        self._alert_history: list[dict] = []

    # ──────────────────────────────
    #  INTERFACE PRINCIPALE
    # ──────────────────────────────

    def send(
        self,
        level:   str,
        title:   str,
        message: str,
        data:    Optional[dict] = None,
    ) -> None:
        """
        Envoie une alerte sur tous les canaux configurés.

        Args:
            level:   AlertLevel constant (INFO/WARNING/CRITICAL/EMERGENCY)
            title:   Titre court de l'alerte
            message: Description détaillée
            data:    Données structurées supplémentaires
        """
        alert = {
            "timestamp": datetime.now().isoformat(),
            "level":     level,
            "title":     title,
            "message":   message,
            "data":      data or {},
        }
        self._alert_history.append(alert)

        emoji = AlertLevel.EMOJIS.get(level, "🔔")

        # ── Console ─────────────────────────────────────────
        log_fn = {
            AlertLevel.INFO:      logger.info,
            AlertLevel.WARNING:   logger.warning,
            AlertLevel.CRITICAL:  logger.critical,
            AlertLevel.EMERGENCY: logger.critical,
        }.get(level, logger.info)

        log_fn(f"{emoji} [{level}] {title} — {message}")

        # ── Notification OS ──────────────────────────────────
        self._notify_os(title, message, level)

        # ── Email ────────────────────────────────────────────
        if ALERT_EMAIL_ENABLED and level in (AlertLevel.CRITICAL, AlertLevel.EMERGENCY):
            self._send_email(title, message, alert)

        # ── Webhook ──────────────────────────────────────────
        if WEBHOOK_ENABLED and WEBHOOK_URL:
            self._send_webhook(alert)

    # ──────────────────────────────
    #  ALERTES PRÉDÉFINIES
    # ──────────────────────────────

    def alert_canary_compromised(
        self, filepath: str, entropy: float,
        delta: float, ml_result: Optional[dict] = None
    ) -> None:
        """Alerte : un fichier canary a été modifié avec entropie suspecte."""
        threat = ml_result.get("threat_level", "?") if ml_result else "?"
        label  = ml_result.get("label", "UNKNOWN") if ml_result else "UNKNOWN"

        self.send(
            level   = AlertLevel.CRITICAL,
            title   = "🚨 CANARY COMPROMIS",
            message = (
                f"Fichier : {filepath} | "
                f"Entropie : {entropy:.2f} bits (Δ+{delta:.2f}) | "
                f"IA : {label} (niveau {threat}/5)"
            ),
            data    = {
                "filepath":  filepath,
                "entropy":   entropy,
                "delta":     delta,
                "ml_result": ml_result,
            }
        )

    def alert_mass_encryption(self, count: int, rate: float) -> None:
        """Alerte : chiffrement de masse en cours."""
        self.send(
            level   = AlertLevel.EMERGENCY,
            title   = "💀 CHIFFREMENT DE MASSE DÉTECTÉ",
            message = (
                f"{count} fichiers modifiés en 60s "
                f"({rate:.1f} fichiers/sec) — Isolation recommandée"
            ),
            data    = {"count": count, "rate": rate}
        )

    def alert_suspicious_rename(self, src: str, dst: str, ext: str) -> None:
        """Alerte : extension ransomware détectée après renommage."""
        self.send(
            level   = AlertLevel.CRITICAL,
            title   = "🔴 EXTENSION RANSOMWARE",
            message = f"{src} → {dst} (ext={ext})",
            data    = {"src": src, "dst": dst, "extension": ext}
        )

    def alert_process_killed(self, pid: int, name: str, success: bool) -> None:
        """Notification de neutralisation d'un processus."""
        status = "✅ succès" if success else "❌ échec"
        self.send(
            level   = AlertLevel.CRITICAL,
            title   = f"🔪 Processus neutralisé ({status})",
            message = f"{name} (PID={pid})",
            data    = {"pid": pid, "name": name, "success": success}
        )

    # ──────────────────────────────
    #  CANAUX PRIVÉS
    # ──────────────────────────────

    @staticmethod
    def _notify_os(title: str, message: str, level: str) -> None:
        """Envoie une notification native OS via plyer."""
        try:
            from plyer import notification
            notification.notify(
                title       = f"[{level}] {title}",
                message     = message[:256],
                app_name    = "RansomwareDetector",
                timeout     = 10,
            )
        except Exception:
            pass  # plyer non installé ou pas de display

    @staticmethod
    def _send_email(subject: str, body: str, alert: dict) -> None:
        """Envoie un email d'alerte via SMTP."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[RANSOMWARE ALERT] {subject}"
            msg["From"]    = ALERT_SMTP_USER
            msg["To"]      = ALERT_EMAIL_TO

            html = f"""
            <html><body style='font-family:monospace;background:#111;color:#0f0;padding:20px'>
              <h2 style='color:#ff4444'>🚨 {subject}</h2>
              <p>{body}</p>
              <pre>{json.dumps(alert, indent=2)}</pre>
            </body></html>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(ALERT_SMTP_HOST, ALERT_SMTP_PORT) as srv:
                srv.starttls()
                srv.login(ALERT_SMTP_USER, ALERT_SMTP_PASS)
                srv.send_message(msg)

            logger.info(f"📧 Email envoyé à {ALERT_EMAIL_TO}")
        except Exception as e:
            logger.error(f"Échec envoi email : {e}")

    @staticmethod
    def _send_webhook(alert: dict) -> None:
        """Envoie l'alerte via webhook (Slack/Teams/Discord compatible)."""
        try:
            # Format Slack-compatible
            payload = json.dumps({
                "text": (
                    f"*[{alert['level']}]* {alert['title']}\n"
                    f"{alert['message']}\n"
                    f"`{alert['timestamp']}`"
                )
            }).encode("utf-8")

            req = urllib.request.Request(
                WEBHOOK_URL,
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )
            urllib.request.urlopen(req, timeout=5)
            logger.info("📡 Webhook envoyé.")
        except Exception as e:
            logger.error(f"Échec webhook : {e}")

    # ──────────────────────────────
    #  HISTORIQUE
    # ──────────────────────────────

    def get_history(self, level: Optional[str] = None) -> list[dict]:
        """Retourne l'historique des alertes, filtrable par niveau."""
        if level:
            return [a for a in self._alert_history if a["level"] == level]
        return list(self._alert_history)

    def critical_count(self) -> int:
        """Nombre d'alertes CRITICAL ou EMERGENCY depuis le démarrage."""
        return sum(
            1 for a in self._alert_history
            if a["level"] in (AlertLevel.CRITICAL, AlertLevel.EMERGENCY)
        )
