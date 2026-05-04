import os
import psutil
import time

def find_and_kill_locker_process(filepath, simulate_only=False, target_script_name="simulate_ransomware.py"):
    """
    Parcourt les processus système et tue celui qui a le fichier ouvert,
    en vérifiant par sécurité qu'il s'agit bien de notre script de simulation (si pas en production pure).
    """
    found = False
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        if process.info.get('name') and process.info['name'].lower() in ['svchost.exe', 'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe']: continue
        try:
            cmdline = process.info.get('cmdline', [])
            name = process.info.get('name', 'N/A')
            pid = process.info.get('pid')
            cmdline_str = " ".join(cmdline) if cmdline else name
            
            # --- OPTIMISATION DEMO (Instantané) ---
            if simulate_only and cmdline and any(target_script_name in arg for arg in cmdline):
                process.terminate()
                gone, alive = psutil.wait_procs([process], timeout=2)
                if process in alive:
                    process.kill()
                return f"🛑 Processus Malveillant INTERCEPTÉ et ARRÊTÉ: PID={pid} | {cmdline_str}"
                
            # Récupérer les fichiers ouverts par le processus
            # L'accès aux open_files() peut déclencher AccessDenied pour les processus système
            open_files = process.open_files()
            for open_file in open_files:
                if os.path.normpath(open_file.path).lower() == os.path.normpath(filepath).lower():
                    found = True
                    cmdline = process.info.get('cmdline', [])
                    name = process.info.get('name', 'N/A')
                    pid = process.info.get('pid')
                    
                    cmdline_str = " ".join(cmdline) if cmdline else name
                    
                    # Sécurité : On ne tue que si on voit "simulate_ransomware" dans la commande
                    # pour éviter de crasher le PC de l'utilisateur.
                    if simulate_only and target_script_name not in cmdline_str:
                        return f"⚠️ Processus trouvé (PID {pid}: {cmdline_str}) mais ignoré par sécurité (simulate_only=True)."
                    
                    # Kill !
                    process.terminate()
                    # Attendre un max de 2 sec pour voir si c'est bon
                    gone, alive = psutil.wait_procs([process], timeout=2)
                    if process in alive:
                        process.kill() # force kill
                        
                    return f"🛑 Processus Malveillant INTERCEPTÉ et ARRÊTÉ: PID={pid} | {cmdline_str}"
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return "ℹ️ Aucun processus n'a été trouvé avec ce fichier ouvert (le fichier a peut-être été fermé rapidement)."
