import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from entropy import calculate_shannon_entropy
from process_killer import find_and_kill_locker_process

ENTROPY_THRESHOLD = 7.5  # Si l'entropie dépasse ce seuil après modification, c'est très louche.

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, callback_alert, callback_info):
        self.callback_alert = callback_alert
        self.callback_info = callback_info
        # Pour éviter de déclencher plusieurs fois l'alerte pour le même fichier en un court laps de temps
        self.last_alerts = {} 
        super().__init__()

    def on_modified(self, event):
        if event.is_directory:
            return

        filepath = event.src_path
        
        # Ignorer les événements trop rapprochés sur le même fichier (debounce)
        current_time = time.time()
        last_alert_time = self.last_alerts.get(filepath, 0)
        if current_time - last_alert_time < 2.0:
            return

        entropy = calculate_shannon_entropy(filepath)
        
        msg = f"Modifié: {os.path.basename(filepath)} | Entropie: {entropy:.2f}"
        self.callback_info(msg)

        if entropy > ENTROPY_THRESHOLD:
            self.last_alerts[filepath] = current_time
            
            # Alerte ransomware
            kill_msg = find_and_kill_locker_process(
                filepath, 
                simulate_only=True,   # Sécurité pour ne pas tuer des apps légitimes lors du test
                target_script_name="simulate_ransomware.py"
            )
            
            alert_details = f"⚠️ [ALERTE CRITIQUE] Chiffrement suspect détecté sur {os.path.basename(filepath)} !\n"
            alert_details += f"Entropie mesurée : {entropy:.2f} > {ENTROPY_THRESHOLD}\n"
            alert_details += f"Action: {kill_msg}"
            
            self.callback_alert(alert_details)

class RansomwareMonitor:
    def __init__(self, directory, callback_alert, callback_info):
        self.directory = directory
        self.callback_alert = callback_alert
        self.callback_info = callback_info
        self.observer = Observer()
        self.is_running = False

    def start(self):
        if not os.path.exists(self.directory):
            self.callback_info(f"Erreur : Le dossier {self.directory} n'existe pas. Déployez les canaris.")
            return

        event_handler = CanaryHandler(self.callback_alert, self.callback_info)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        self.is_running = True
        self.callback_info(f"Monitorage activé sur : {self.directory}")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            self.callback_info("Monitorage arrêté.")
