"""
monitor/watcher.py — Surveillance filesystem avec Watchdog

Surveille en temps réel :
  - Les fichiers Canary (priorité maximale)
  - Les modifications de masse (> seuil fichiers/min)
  - Les renommages suspects (ajout d'extensions étranges)
"""

import sys
import time
import logging
import threading
from pathlib import Path
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileModifiedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    MASS_MOD_THRESHOLD, MASS_MOD_WINDOW_SEC,
    MAX_WORKER_THREADS, WATCHER_TIMEOUT
)

logger = logging.getLogger("RansomwareDetector.Watcher")

# Extensions souvent ajoutées par les ransomwares
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
    ".locky", ".zepto", ".cerber", ".zzzzz", ".micro",
    ".vault", ".wnry", ".wncry", ".wcry", ".wcryt",
    ".lockbit", ".lbik", ".revil", ".sodinokibi", ".r4ns",
}


# ──────────────────────────────────────────────────────────────
#  HANDLER WATCHDOG
# ──────────────────────────────────────────────────────────────

class RansomwareEventHandler(FileSystemEventHandler):
    """
    Handler Watchdog qui filtre et dispatche les événements suspects.

    Callbacks injectés :
      on_canary_modified(filepath, event_type)
      on_mass_modification(count, rate)
      on_suspicious_rename(src, dst, new_ext)
    """

    def __init__(
        self,
        canary_manager,
        on_canary_modified:    Optional[Callable] = None,
        on_mass_modification:  Optional[Callable] = None,
        on_suspicious_rename:  Optional[Callable] = None,
    ):
        super().__init__()
        self.canary_manager       = canary_manager
        self._on_canary_modified  = on_canary_modified
        self._on_mass_mod         = on_mass_modification
        self._on_suspicious_rename = on_suspicious_rename

        # Fenêtre glissante pour la détection de masse
        from analysis.features import SlidingWindowCounter
        self._mod_counter = SlidingWindowCounter(MASS_MOD_WINDOW_SEC)
        self._lock        = threading.Lock()

    # ──────────────────────────────
    #  ÉVÉNEMENTS WATCHDOG
    # ──────────────────────────────

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "MODIFIED")

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        self._handle_file_event(event.src_path, "CREATED")

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if event.is_directory:
            return
        # Suppression d'un canary = compromission immédiate
        if self.canary_manager.is_canary(event.src_path):
            logger.critical(f"🚨 CANARY SUPPRIMÉ : {event.src_path}")
            if self._on_canary_modified:
                self._on_canary_modified(event.src_path, "DELETED")

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        self._handle_rename(event.src_path, event.dest_path)

    # ──────────────────────────────
    #  LOGIQUE DE TRAITEMENT
    # ──────────────────────────────

    def _handle_file_event(self, filepath: str, event_type: str) -> None:
        """Traite un événement de modification ou création."""
        # Comptage pour détection de masse
        with self._lock:
            self._mod_counter.record()
            count = self._mod_counter.count()
            rate  = self._mod_counter.rate_per_second()

        # Alerte masse
        if count >= MASS_MOD_THRESHOLD:
            logger.warning(
                f"⚠️  MASSE : {count} fichiers modifiés en {MASS_MOD_WINDOW_SEC}s "
                f"({rate:.2f}/sec)"
            )
            if self._on_mass_mod:
                self._on_mass_mod(count, rate)

        # Alerte canary
        if self.canary_manager.is_canary(filepath):
            logger.critical(
                f"🚨 CANARY TOUCHÉ [{event_type}] : {filepath}"
            )
            if self._on_canary_modified:
                self._on_canary_modified(filepath, event_type)

    def _handle_rename(self, src: str, dst: str) -> None:
        """Détecte les renommages avec extensions suspectes."""
        dst_path = Path(dst)
        new_ext  = dst_path.suffix.lower()

        # Renommage d'un canary
        if self.canary_manager.is_canary(src):
            logger.critical(f"🚨 CANARY RENOMMÉ : {src} → {dst}")
            if self._on_canary_modified:
                self._on_canary_modified(src, "RENAMED")

        # Extension ransomware détectée
        if new_ext in RANSOMWARE_EXTENSIONS:
            logger.critical(
                f"🔴 EXTENSION RANSOMWARE : {src} → {dst} (ext={new_ext})"
            )
            if self._on_suspicious_rename:
                self._on_suspicious_rename(src, dst, new_ext)

        # Comptage des renommages
        with self._lock:
            self._mod_counter.record()


# ──────────────────────────────────────────────────────────────
#  WATCHER PRINCIPAL
# ──────────────────────────────────────────────────────────────

class FileSystemWatcher:
    """
    Orchestre la surveillance multi-répertoires avec Watchdog.

    Usage :
        watcher = FileSystemWatcher(canary_manager)
        watcher.on_canary_modified = my_callback
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        canary_manager,
        watch_dirs: Optional[list[Path]] = None,
    ):
        self.canary_manager = canary_manager
        self.watch_dirs     = watch_dirs or canary_manager.canary_dirs

        # Callbacks publics (à injecter avant start())
        self.on_canary_modified:   Optional[Callable] = None
        self.on_mass_modification: Optional[Callable] = None
        self.on_suspicious_rename: Optional[Callable] = None

        self._observer:  Optional[Observer]        = None
        self._executor:  Optional[ThreadPoolExecutor] = None
        self._event_queue: Queue                   = Queue()
        self._running    = False

    def start(self) -> None:
        """Démarre la surveillance et les workers d'analyse."""
        if self._running:
            return

        handler = RansomwareEventHandler(
            canary_manager       = self.canary_manager,
            on_canary_modified   = self._queue_canary_event,
            on_mass_modification = self.on_mass_modification,
            on_suspicious_rename = self.on_suspicious_rename,
        )

        self._observer = Observer(timeout=WATCHER_TIMEOUT)

        for directory in self.watch_dirs:
            directory = Path(directory).expanduser()
            if directory.exists():
                self._observer.schedule(handler, str(directory), recursive=True)
                logger.info(f"👁  Surveillance : {directory}")
            else:
                logger.warning(f"⚠️  Répertoire inexistant ignoré : {directory}")

        self._executor = ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS)
        self._observer.start()
        self._running = True
        logger.info("✅ Watcher démarré.")

    def stop(self) -> None:
        """Arrête proprement la surveillance."""
        if not self._running:
            return
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()
        if self._executor:
            self._executor.shutdown(wait=False)
        logger.info("🛑 Watcher arrêté.")

    def _queue_canary_event(self, filepath: str, event_type: str) -> None:
        """Enqueue l'événement canary pour traitement asynchrone."""
        self._event_queue.put((filepath, event_type))
        if self.on_canary_modified:
            self._executor.submit(self.on_canary_modified, filepath, event_type)

    def is_running(self) -> bool:
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
