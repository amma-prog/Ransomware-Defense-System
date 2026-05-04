"""
tests/test_entropy.py — Tests unitaires du module analysis/entropy.py
Lancer : pytest tests/test_entropy.py -v
"""

import sys
import math
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "analysis"))

from entropy import (
    calculate_entropy,
    calculate_entropy_bytes,
    classify_entropy,
    get_entropy_delta,
    is_suspicious,
    entropy_report,
)


# ──────────────────────────────────────────────────────────────
#  FIXTURES : génération de données test
# ──────────────────────────────────────────────────────────────

def make_temp_file(content: bytes) -> Path:
    """Crée un fichier temporaire avec le contenu donné."""
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return Path(path)


# Données de test représentatives
TEXT_DATA       = b"Hello world! This is a normal text file with low entropy." * 100
RANDOM_DATA     = bytes(range(256)) * 400          # Entropie maximale ~8.0
ENCRYPTED_SIM   = bytes([i ^ 0xAB for i in range(256)] * 400)  # XOR ~7.99
EMPTY_DATA      = b""
SINGLE_BYTE     = b"\x00" * 1000                   # Entropie = 0


# ──────────────────────────────────────────────────────────────
#  TESTS calculate_entropy_bytes
# ──────────────────────────────────────────────────────────────

class TestEntropyBytes:
    def test_empty_returns_zero(self):
        assert calculate_entropy_bytes(EMPTY_DATA) == 0.0

    def test_single_byte_value_returns_zero(self):
        assert calculate_entropy_bytes(SINGLE_BYTE) == 0.0

    def test_text_entropy_low(self):
        val = calculate_entropy_bytes(TEXT_DATA)
        assert 3.0 <= val <= 6.0, f"Attendu 3–6, obtenu {val}"

    def test_random_entropy_near_max(self):
        val = calculate_entropy_bytes(RANDOM_DATA)
        assert val >= 7.9, f"Attendu ≥7.9, obtenu {val}"

    def test_encrypted_sim_high(self):
        val = calculate_entropy_bytes(ENCRYPTED_SIM)
        assert val >= 7.9, f"Attendu ≥7.9, obtenu {val}"

    def test_value_bounded(self):
        for data in [TEXT_DATA, RANDOM_DATA, ENCRYPTED_SIM, SINGLE_BYTE]:
            val = calculate_entropy_bytes(data)
            assert 0.0 <= val <= 8.0, f"Hors bornes : {val}"

    def test_return_type_is_float(self):
        assert isinstance(calculate_entropy_bytes(TEXT_DATA), float)


# ──────────────────────────────────────────────────────────────
#  TESTS calculate_entropy (fichiers)
# ──────────────────────────────────────────────────────────────

class TestEntropyFile:
    def test_text_file_low_entropy(self):
        p = make_temp_file(TEXT_DATA)
        try:
            val = calculate_entropy(p)
            assert 3.0 <= val <= 6.0
        finally:
            p.unlink()

    def test_random_file_high_entropy(self):
        p = make_temp_file(RANDOM_DATA)
        try:
            val = calculate_entropy(p)
            assert val >= 7.9
        finally:
            p.unlink()

    def test_missing_file_returns_minus_one(self):
        val = calculate_entropy("/nonexistent/path/file.txt")
        assert val == -1.0

    def test_empty_file_returns_zero(self):
        p = make_temp_file(EMPTY_DATA)
        try:
            val = calculate_entropy(p)
            assert val == 0.0
        finally:
            p.unlink()

    def test_consistency_file_vs_bytes(self):
        """calculate_entropy et calculate_entropy_bytes doivent donner le même résultat."""
        p = make_temp_file(TEXT_DATA)
        try:
            file_val  = calculate_entropy(p)
            bytes_val = calculate_entropy_bytes(TEXT_DATA)
            assert abs(file_val - bytes_val) < 0.001
        finally:
            p.unlink()


# ──────────────────────────────────────────────────────────────
#  TESTS classify_entropy
# ──────────────────────────────────────────────────────────────

class TestClassifyEntropy:
    def test_error_label(self):
        assert classify_entropy(-1.0) == "ERROR"

    def test_normal_label(self):
        assert classify_entropy(3.5) == "NORMAL"
        assert classify_entropy(5.9) == "NORMAL"

    def test_warning_label(self):
        assert classify_entropy(6.5) == "WARNING"
        assert classify_entropy(7.1) == "WARNING"

    def test_critical_label(self):
        assert classify_entropy(7.5) == "CRITICAL"
        assert classify_entropy(7.99) == "CRITICAL"


# ──────────────────────────────────────────────────────────────
#  TESTS is_suspicious
# ──────────────────────────────────────────────────────────────

class TestIsSuspicious:
    def test_high_entropy_is_suspicious(self):
        suspect, reason = is_suspicious(7.8)
        assert suspect is True
        assert len(reason) > 0

    def test_low_entropy_not_suspicious(self):
        suspect, _ = is_suspicious(4.0)
        assert suspect is False

    def test_big_delta_is_suspicious(self):
        suspect, reason = is_suspicious(current_entropy=6.5, baseline_entropy=4.0)
        assert suspect is True  # delta = 2.5 > 1.5

    def test_small_delta_not_suspicious(self):
        suspect, _ = is_suspicious(current_entropy=4.5, baseline_entropy=4.0)
        assert suspect is False  # delta = 0.5 < 1.5

    def test_returns_tuple(self):
        result = is_suspicious(5.0)
        assert isinstance(result, tuple) and len(result) == 2


# ──────────────────────────────────────────────────────────────
#  TESTS entropy_report
# ──────────────────────────────────────────────────────────────

class TestEntropyReport:
    def test_report_has_required_keys(self):
        p = make_temp_file(TEXT_DATA)
        try:
            report = entropy_report(p, baseline=3.5)
            required = {"filepath", "filename", "entropy", "baseline",
                        "delta", "status", "suspicious", "reason", "file_size"}
            assert required.issubset(report.keys())
        finally:
            p.unlink()

    def test_report_delta_correct(self):
        p = make_temp_file(RANDOM_DATA)
        try:
            report = entropy_report(p, baseline=4.0)
            expected_delta = round(report["entropy"] - 4.0, 4)
            assert abs(report["delta"] - expected_delta) < 0.001
        finally:
            p.unlink()

    def test_report_suspicious_flag_on_encrypted(self):
        p = make_temp_file(ENCRYPTED_SIM)
        try:
            report = entropy_report(p, baseline=3.5)
            assert report["suspicious"] is True
        finally:
            p.unlink()
