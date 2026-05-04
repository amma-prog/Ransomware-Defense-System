# Rapport de Projet : Détection Proactive de Ransomwares (CanaryShield)

## 1. Introduction
L'objectif de ce projet est de concevoir et développer un système de défense multiniveau contre les attaques de type Ransomware. Face à l'évolution des malwares (attaques Zero-Day) qui contournent les antivirus basés sur les signatures classiques, nous avons opté pour une approche hybride combinant l'Intelligence Artificielle (Machine Learning) et une architecture de Leurres (Honeypot) avec analyse mathématique en temps réel.

## 2. Architecture Globale du Projet
Le projet a été divisé en deux phases distinctes pour garantir à la fois la précision scientifique et la performance en production :

### Phase 1 : Étude et Modélisation (Machine Learning)
- **Objectif** : Identifier les caractéristiques (Features) les plus fiables d'une attaque par chiffrement.
- **Modèles utilisés** : 
  - **Random Forest (Supervisé)** : Entraîné sur 13 000 échantillons avec 9 features (Entropie, Delta, Rate, Renames, VSS...). Il a prouvé que l'**Entropie de Shannon** représente 70% du poids décisionnel lors d'un chiffrement.
  - **Isolation Forest (Non-Supervisé)** : Implémenté pour détecter les anomalies et contrer les nouvelles variantes de ransomwares (Zero-Day) en se basant uniquement sur la déviation du comportement "normal".

### Phase 2 : Déploiement Temps-Réel (CanaryShield)
- **Objectif** : Créer un système de défense ultra-léger et instantané basé sur la meilleure feature découverte (L'Entropie).
- **Principe** : Le système déploie des fichiers pièges (Canaris). Puisqu'aucun utilisateur légitime ne modifie ces fichiers cachés, toute altération de leur entropie est garantie comme étant l'œuvre d'un ransomware (Zéro Faux Positif).

---

## 3. Détails Techniques des Composants (Phase 2)

### A. Gestionnaire de Canaris (`canary_manager.py`)
- **Déploiement** : Génération de faux fichiers attractifs (`passwords_backup.txt`, `finances_2024.csv`) dans un répertoire de surveillance.
- **Sauvegarde** : Création simultanée d'une copie saine (Backup) cachée.
- **Restauration** : Mécanisme permettant de réécraser les fichiers compromis par leur version saine en un clic après neutralisation de l'attaque.

### B. Moteur de Surveillance et Entropie (`monitor.py` & `entropy.py`)
- **Watchdog** : Utilisation de la librairie `watchdog` pour écouter les événements du système de fichiers (Création, Modification) avec une latence quasi nulle.
- **Analyse Mathématique** : À chaque modification, le système calcule l'**Entropie de Shannon**.
- **Seuil d'alerte** : Si l'entropie dépasse le seuil critique de `7.5` (indiquant un chiffrement de niveau AES/RSA), l'alerte est déclenchée.

### C. Système d'Intervention (`process_killer.py`)
- **Détection du Processus** : Utilisation de la librairie `psutil` pour scanner la table des processus Windows et identifier le PID (Process ID) qui maintient le fichier canari ouvert.
- **Neutralisation** : Envoi d'un signal `SIGTERM` / `SIGKILL` pour tuer instantanément le processus malveillant avant qu'il ne puisse chiffrer les vrais fichiers de l'utilisateur.

### D. Interface d'Administration (`web_app.py` & `dashboard.html`)
- **Backend Flask** : Serveur web asynchrone gérant l'API.
- **WebSockets (Socket.IO)** : Communication bidirectionnelle permettant de mettre à jour les graphiques de l'interface en temps réel (affichage des scores d'entropie) sans rafraîchir la page.
- **Contrôles** : Boutons de déploiement, démarrage de la surveillance, et restauration.

### E. Forensique et Audit (`db_manager.py` & `report_generator.py`)
- **Base de données SQLite** : Enregistrement persistant de toutes les alertes (Date, Heure, Fichier attaqué, Score d'entropie, Action entreprise).
- **Génération PDF** : Exportation d'un rapport formel (Forensic Report) via la librairie `fpdf2` pour fournir des preuves de l'attaque à une équipe SOC (Security Operations Center).

---

## 4. Scénario de Simulation et Validation
Pour valider le système, un script de simulation (`simulate_ransomware.py`) a été développé :
1. Il cible un fichier canari et remplace son contenu par des octets aléatoires (chiffrement simulé).
2. L'entropie du fichier passe brusquement de ~4.0 à ~7.9.
3. Le `CanaryHandler` détecte le pic, déclenche l'alarme sonore, journalise l'alerte en BDD, et ordonne au `process_killer` d'éliminer le script de simulation.
4. Le processus est "tué" de force, validant ainsi la réactivité de la chaîne de défense.

## 5. Perspectives d'Amélioration (Microservices)
La prochaine étape d'évolution de cette architecture consisterait à héberger le modèle de Machine Learning (Random Forest) développé en Phase 1 sous forme d'**API REST (FastAPI)**. Le Dashboard `CanaryShield` pourrait ainsi interroger cette API en temps réel pour analyser les vrais documents de l'utilisateur de manière asynchrone, combinant ainsi la précision absolue de l'IA avec la rapidité des Canaris.
