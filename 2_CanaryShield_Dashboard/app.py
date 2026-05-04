import customtkinter as ctk
import os
import threading

from canary_manager import CanaryManager
from monitor import RansomwareMonitor
from alarm import AlarmSystem

# Configuration de CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CanaryShield - Ransomware Early Detection")
        self.geometry("800x600")

        # Initialisation composants métier
        base_path = os.path.dirname(os.path.abspath(__file__))
        self.canary_mgr = CanaryManager(base_path)
        self.monitor = RansomwareMonitor(self.canary_mgr.get_canary_dir(), self.on_alert, self.on_info)
        self.alarm = AlarmSystem()

        self.create_widgets()

    def create_widgets(self):
        # Frame pour les contrôles (gauche)
        self.controls_frame = ctk.CTkFrame(self, width=250)
        self.controls_frame.pack(side="left", fill="y", padx=10, pady=10)

        # Boutons
        self.btn_deploy = ctk.CTkButton(self.controls_frame, text="1. Déployer Leurres (Canaris)", command=self.deploy_canaries)
        self.btn_deploy.pack(pady=20, padx=20, fill="x")

        self.btn_start = ctk.CTkButton(self.controls_frame, text="2. Lancer la Surveillance", fg_color="green", command=self.start_monitor)
        self.btn_start.pack(pady=20, padx=20, fill="x")

        self.btn_stop = ctk.CTkButton(self.controls_frame, text="3. Arrêter la Surveillance", fg_color="gray", command=self.stop_monitor)
        self.btn_stop.pack(pady=20, padx=20, fill="x")
        self.btn_stop.configure(state="disabled")

        self.btn_restore = ctk.CTkButton(self.controls_frame, text="4. Restaurer les Fichiers", fg_color="#b35900", hover_color="#cc6600", command=self.restore_canaries)
        self.btn_restore.pack(pady=20, padx=20, fill="x")

        self.status_label = ctk.CTkLabel(self.controls_frame, text="Statut : INACTIF", font=("Arial", 14, "bold"), text_color="yellow")
        self.status_label.pack(pady=40, padx=20)

        # Frame pour les logs (droite)
        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.log_label = ctk.CTkLabel(self.log_frame, text="Journal système et Alertes :", font=("Arial", 14, "bold"))
        self.log_label.pack(pady=10, anchor="w", padx=10)

        self.textbox = ctk.CTkTextbox(self.log_frame, font=("Courier", 12))
        self.textbox.pack(fill="both", expand=True, padx=10, pady=10)
        
    def log_message(self, message, is_alert=False):
        """Thread-safe l'ajout de log dans la textbox."""
        def insert_log():
            self.textbox.insert("end", f"> {message}\n")
            if is_alert:
                self.textbox.insert("end", "-"*50 + "\n")
            self.textbox.see("end")
            
        # L'utilisation de after permet d'exécuter la fonction dans le thread principal (Tkinter)
        self.after(0, insert_log)

    def on_info(self, message):
        self.log_message(message, False)

    def on_alert(self, message):
        self.log_message(message, True)
        # Déclencher l'alarme sonore
        self.alarm.trigger()
        # Changer la couleur en rouge en cas d'alerte
        def set_alert_status():
            self.status_label.configure(text="Statut : ALERTE RANSOMWARE !", text_color="red")
            self.configure(fg_color="#330000") # fond léger rouge
        self.after(0, set_alert_status)

    def deploy_canaries(self):
        dir_created = self.canary_mgr.deploy_canaries()
        self.log_message(f"Leurres recréés dans {dir_created}")

    def start_monitor(self):
        if not os.path.exists(self.canary_mgr.get_canary_dir()):
            self.log_message("Veuillez déployer les leurres en premier.")
            return

        self.monitor.start()
        self.btn_start.configure(state="disabled", fg_color="gray")
        self.btn_stop.configure(state="normal", fg_color="red")
        
        self.status_label.configure(text="Statut : SURVEILLANCE ACTIVE", text_color="green")
        self.configure(fg_color="#242424") # reset fond par défaut ctk (dark mode)

    def stop_monitor(self):
        self.monitor.stop()
        self.alarm.stop()
        self.btn_stop.configure(state="disabled", fg_color="gray")
        self.btn_start.configure(state="normal", fg_color="green")
        
        self.status_label.configure(text="Statut : INACTIF", text_color="yellow")

    def restore_canaries(self):
        self.alarm.stop()
        success, message = self.canary_mgr.restore_canaries()
        if success:
            self.log_message(f"✅ {message}")
            # Réinitialiser le statut si on était en mode alerte
            def reset_status():
                self.status_label.configure(text="Statut : FICHIERS RESTAURÉS", text_color="#00cc66")
                self.configure(fg_color="#242424")
            self.after(0, reset_status)
        else:
            self.log_message(f"❌ {message}")

    def destroy(self):
        self.monitor.stop()
        super().destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()
