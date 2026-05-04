import os
import time
import random
import glob

def simulate_encryption():
    base_path = os.path.dirname(os.path.abspath(__file__))
    canary_dir = os.path.join(base_path, "demo_canaries")

    if not os.path.exists(canary_dir):
        print("Erreur : Le dossier de leurres n'existe pas. Lancez le déploiement depuis l'interface principale d'abord.")
        return

    # Chercher un fichier texte à chiffrer
    txt_files = glob.glob(os.path.join(canary_dir, "*.txt"))
    if not txt_files:
        print("Erreur : Aucun fichier .txt trouvé dans le dossier leurres.")
        return

    target_file = random.choice(txt_files)
    print(f"Ransomware simulé démarré sur : {target_file}")
    
    # 1. Ouvrir le fichier
    try:
        with open(target_file, "r+b") as f: # r+b : lire/écrire en binaire
            content = f.read()
            if not content:
                content = b"fake data"
            
            # Revenir au début pour écraser
            f.seek(0)
            
            # Générer du contenu haute entropie (des octets aléatoires, l'entropie ~ 8.0)
            print("Chiffrement en cours...")
            encrypted_content = os.urandom(len(content) + 1024)
            
            f.write(encrypted_content)
            f.truncate()
            
            # Forcer l'écriture sur le disque immédiatement pour que Watchdog le voie
            f.flush()
            os.fsync(f.fileno())
            
            print("Chiffrement terminé. Le moniteur devrait avoir réagi.")
            print("Je maintiens le fichier ouvert pendant 30 secondes pour que l'antivirus puisse me détecter via 'process_killer.py'.")
            
            # C'est ici que le moniteur doit nous tuer
            for _ in range(30):
                time.sleep(1)
                print(".", end="", flush=True)

    except PermissionError:
         print(f"Permission refusée. Le fichier {target_file} est peut-être verrouillé.")
    except Exception as e:
         print(f"Erreur inattendue : {e}")

if __name__ == "__main__":
    simulate_encryption()
    print("\nSimulation finie. Si le script n'a pas été coupé automatiquement, la détection a peut-être échouée.")
