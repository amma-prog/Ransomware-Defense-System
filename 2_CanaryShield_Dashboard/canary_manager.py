import os
import shutil
import datetime

class CanaryManager:
    def __init__(self, base_path):
        self.canary_dir = os.path.join(base_path, "demo_canaries")
        self.backup_dir = os.path.join(base_path, "canary_backups")

    def deploy_canaries(self):
        """
        Crée le dossier et génère des fichiers de leurre (faible entropie).
        """
        # Nettoyer s'il existe déjà
        if os.path.exists(self.canary_dir):
            shutil.rmtree(self.canary_dir)
            
        os.makedirs(self.canary_dir)

        # Fichiers à générer
        files_to_create = [
            "passwords_backup.txt",
            "finances_2024.csv",
            "secret_project.docx",
            "personal_diary.txt"
        ]

        # Remplir avec du texte répétitif / structuré (faible entropie)
        content_txt = "Ceci est un fichier texte normal. " * 50
        content_csv = "id,name,amount\n1,Alpha,100\n2,Beta,200\n" * 20
        content_docx = "Ceci simule un document word avec du texte brut pour le test. " * 40

        for file_name in files_to_create:
            file_path = os.path.join(self.canary_dir, file_name)
            content = ""
            
            if file_name.endswith('.txt'):
                content = content_txt
            elif file_name.endswith('.csv'):
                content = content_csv
            elif file_name.endswith('.docx'):
                content = content_docx

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
                
        print(f"[{len(files_to_create)}] Fichiers canaris déployés dans : {self.canary_dir}")

        # Créer une sauvegarde automatique
        self._create_backup()

        return self.canary_dir

    def _create_backup(self):
        """
        Copie tous les fichiers canaris dans le dossier de sauvegarde.
        """
        if os.path.exists(self.backup_dir):
            shutil.rmtree(self.backup_dir)
        
        shutil.copytree(self.canary_dir, self.backup_dir)
        print(f"Sauvegarde créée dans : {self.backup_dir}")

    def restore_canaries(self):
        """
        Restaure les fichiers canaris depuis la sauvegarde.
        Retourne (success: bool, message: str)
        """
        if not os.path.exists(self.backup_dir):
            return False, "Aucune sauvegarde trouvée. Déployez les canaris d'abord."

        restored_count = 0
        for filename in os.listdir(self.backup_dir):
            src = os.path.join(self.backup_dir, filename)
            dst = os.path.join(self.canary_dir, filename)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                restored_count += 1

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        return True, f"[{timestamp}] {restored_count} fichier(s) restauré(s) depuis la sauvegarde."

    def has_backup(self):
        """Vérifie si une sauvegarde existe."""
        return os.path.exists(self.backup_dir) and len(os.listdir(self.backup_dir)) > 0

    def get_canary_dir(self):
        return self.canary_dir
