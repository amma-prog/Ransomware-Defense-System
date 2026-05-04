"""
canary/canary_manager.py — Création, déploiement et gestion des fichiers leurres

Les fichiers Canary imitent des cibles à haute valeur perçue pour les ransomwares
(mots de passe, données financières, clés privées…). Leur entropie baseline est
enregistrée au déploiement pour détecter toute modification chiffrée.
"""

import os
import json
import struct
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    CANARY_DIRS, CANARY_COUNT, CANARY_HIDDEN,
    CANARY_STATE_FILE, BASE_DIR
)

# Import local (relatif au package)
sys.path.insert(0, str(Path(__file__).parent.parent / "analysis"))
from entropy import calculate_entropy


# ──────────────────────────────────────────────────────────────
#  TEMPLATES DE FICHIERS APPÂTS
#  Chaque template simule un fichier réaliste à entropie naturelle
# ──────────────────────────────────────────────────────────────

def _make_excel_header() -> bytes:
    """Header PK (ZIP/XLSX) factice pour imiter un fichier Excel."""
    pk_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    content   = b"financial_report_fake_content_" * 200
    return pk_header + content


def _make_word_header() -> bytes:
    """Header DOCX factice."""
    pk_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    content   = b"contract_document_fake_content_" * 200
    return pk_header + content


CANARY_TEMPLATES: list[tuple[str, bytes]] = [
    # (nom_du_fichier, contenu_bytes)
    (
        "passwords_backup.txt",
        (
            "# Backup des mots de passe - CONFIDENTIEL\n"
            "admin:P@ssw0rd!2024\n"
            "root:Sup3r$ecret\n"
            "mysql_root:Db@2024!\n"
            "ftp_user:Ftp#Pass99\n"
            "vpn_key:Vpn@Corp2024\n"
            "backup_admin:Bkp$2024!\n"
            "email_account:M@il2024!\n"
        ).encode() * 20,
    ),
    (
        "financial_report_2024.xlsx",
        _make_excel_header(),
    ),
    (
        "client_database.csv",
        (
            "id,name,email,phone,credit_card\n"
            + "\n".join(
                f"{i},Client{i},client{i}@corp.com,+33600{i:06d},4111-1111-1111-{i:04d}"
                for i in range(1, 300)
            )
        ).encode(),
    ),
    (
        "private_keys.pem",
        (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + ("MIIEpAIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29a2jT\n" * 30)
            + "-----END RSA PRIVATE KEY-----\n"
        ).encode() * 3,
    ),
    (
        "company_contracts_2024.docx",
        _make_word_header(),
    ),
    (
        "hr_employee_list.csv",
        (
            "id,firstname,lastname,salary,ssn\n"
            + "\n".join(
                f"{i},Firstname{i},Lastname{i},{30000+i*100},***-**-{i:04d}"
                for i in range(1, 200)
            )
        ).encode(),
    ),
    (
        "vpn_config_backup.ovpn",
        (
            "client\ndev tun\nproto udp\n"
            "remote vpn.corp.internal 1194\n"
            "ca ca.crt\ncert client.crt\nkey client.key\n"
            "cipher AES-256-CBC\nauth SHA256\n"
            "# Corp VPN - DO NOT SHARE\n"
        ).encode() * 50,
    ),
    (
        "tax_declaration_2023.pdf",
        (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"% Fake tax document canary\n" * 300
        ),
    ),
    (
        "ssh_id_rsa",
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + ("b3BlbnNzaC1rZXktdjEAAAAA" * 40 + "\n")
            + "-----END OPENSSH PRIVATE KEY-----\n"
        ).encode() * 3,
    ),
    (
        "wallet_backup.dat",
        (
            "# Bitcoin Wallet Backup\n"
            "mnemonic=abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about\n"
            "xpub=xpub661MyMwAqRbcFakeWalletKeyForCanaryDetection\n"
        ).encode() * 30,
    ),
]


# ──────────────────────────────────────────────────────────────
#  CANARY MANAGER
# ──────────────────────────────────────────────────────────────

class CanaryManager:
    """
    Gère le cycle de vie complet des fichiers leurres :
    création, baseline, surveillance et nettoyage.
    """

    def __init__(
        self,
        canary_dirs: Optional[list[Path]] = None,
        count: int = CANARY_COUNT,
        state_file: Path = CANARY_STATE_FILE,
    ):
        self.canary_dirs   = canary_dirs or CANARY_DIRS
        self.count         = min(count, len(CANARY_TEMPLATES))
        self.state_file    = Path(state_file)
        self.canary_files: list[str]    = []
        self.baselines:    dict[str, float] = {}
        self._deployed     = False

    # ──────────────────────────────
    #  DÉPLOIEMENT
    # ──────────────────────────────

    def deploy(self) -> list[str]:
        """
        Déploie les fichiers canary dans tous les répertoires cibles.
        Enregistre les entropies baseline. Persiste l'état sur disque.

        Returns:
            Liste des chemins absolus des fichiers déployés.
        """
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        deployed = []

        for target_dir in self.canary_dirs:
            try:
                target_dir = Path(target_dir).expanduser()
                target_dir.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError):
                continue

            for name, content in CANARY_TEMPLATES[: self.count]:
                filepath = target_dir / name
                
                # FIX: Sur Windows, ouvrir un fichier caché en 'wb' lève une PermissionError
                # On doit d'abord retirer l'attribut caché et le supprimer s'il existe déjà
                if filepath.exists():
                    try:
                        if platform.system() == "Windows":
                            subprocess.run(["attrib", "-H", str(filepath)], capture_output=True, check=False)
                        filepath.unlink()
                    except Exception:
                        pass
                
                try:
                    with filepath.open("wb") as fh:
                        fh.write(content)
                    if CANARY_HIDDEN:
                        self._set_hidden(filepath)
                    deployed.append(str(filepath))
                except (OSError, PermissionError) as e:
                    # Ignore les dossiers bloqués par UAC
                    continue

        self.canary_files = deployed
        self._record_baselines()
        self._save_state()
        self._deployed = True
        return deployed

    # ──────────────────────────────
    #  BASELINE
    # ──────────────────────────────

    def _record_baselines(self) -> None:
        """Calcule et stocke l'entropie initiale de chaque canary."""
        for fp in self.canary_files:
            entropy = calculate_entropy(fp)
            self.baselines[fp] = entropy

    def get_baseline(self, filepath: str) -> float:
        """
        Retourne l'entropie baseline enregistrée pour un fichier.
        Returns 0.0 si le fichier n'est pas dans le registre.
        """
        return self.baselines.get(str(filepath), 0.0)

    def is_canary(self, filepath: str) -> bool:
        """Vérifie si un chemin correspond à un fichier canary."""
        return str(filepath) in self.canary_files

    # ──────────────────────────────
    #  PERSISTANCE DE L'ÉTAT
    # ──────────────────────────────

    def _save_state(self) -> None:
        """Sauvegarde l'état complet en JSON (chemins + baselines)."""
        state = {
            "deployed_at": datetime.now().isoformat(),
            "files":       self.canary_files,
            "baselines":   self.baselines,
        }
        with self.state_file.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)

    def load_state(self) -> bool:
        """
        Recharge un état précédent depuis le fichier JSON.
        Utile pour reprendre la surveillance après un redémarrage.

        Returns:
            True si l'état a été chargé avec succès.
        """
        if not self.state_file.exists():
            return False
        try:
            with self.state_file.open("r", encoding="utf-8") as fh:
                state = json.load(fh)
            self.canary_files = state.get("files", [])
            self.baselines    = state.get("baselines", {})
            self._deployed    = bool(self.canary_files)
            return True
        except (json.JSONDecodeError, KeyError):
            return False

    # ──────────────────────────────
    #  NETTOYAGE
    # ──────────────────────────────

    def cleanup(self) -> int:
        """
        Supprime tous les fichiers canary déployés.

        Returns:
            Nombre de fichiers supprimés avec succès.
        """
        removed = 0
        for fp in self.canary_files:
            try:
                Path(fp).unlink(missing_ok=True)
                removed += 1
            except (OSError, PermissionError):
                pass

        self.canary_files.clear()
        self.baselines.clear()

        if self.state_file.exists():
            self.state_file.unlink(missing_ok=True)

        self._deployed = False
        return removed

    # ──────────────────────────────
    #  UTILITAIRES
    # ──────────────────────────────

    @staticmethod
    def _set_hidden(filepath: Path) -> None:
        """Rend le fichier invisible dans l'explorateur (Windows/Linux)."""
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["attrib", "+H", str(filepath)],
                    check=False, capture_output=True
                )
            else:
                # Convention Unix : préfixer par un point
                hidden_path = filepath.parent / f".{filepath.name}"
                filepath.rename(hidden_path)
        except Exception:
            pass  # Non critique

    def status_report(self) -> dict:
        """Retourne un résumé du statut de tous les canary déployés."""
        report = {
            "total_deployed": len(self.canary_files),
            "deployed":       self._deployed,
            "files":          [],
        }
        for fp in self.canary_files:
            p = Path(fp)
            report["files"].append({
                "path":      fp,
                "exists":    p.exists(),
                "baseline":  self.baselines.get(fp, 0.0),
                "current_entropy": calculate_entropy(fp) if p.exists() else -1.0,
            })
        return report

    def __repr__(self) -> str:
        return (
            f"CanaryManager("
            f"deployed={self._deployed}, "
            f"files={len(self.canary_files)}, "
            f"dirs={len(self.canary_dirs)})"
        )
