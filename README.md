# 🛡️ Système de Défense Proactif contre les Ransomwares

Ce projet est un système complet de détection et neutralisation de ransomwares, divisé en deux modules complémentaires.

## 📂 Architecture du Projet

### 1️⃣ [Moteur de Machine Learning](./1_Machine_Learning_Engine/)
Phase d'étude et d'entraînement de modèles d'IA.
- **Modèles** : Random Forest (Supervisé) et Isolation Forest (Non-supervisé / Zero-Day).
- **Rôle** : Analyse approfondie de 9 caractéristiques (Features) pour différencier les modifications normales (ex: compression ZIP) des chiffrements malveillants, en évitant les faux positifs.
- *Voir le README dans le dossier pour plus de détails.*

### 2️⃣ [Dashboard Temps-Réel (CanaryShield)](./2_CanaryShield_Dashboard/)
L'interface de production et de surveillance instantanée.
- **Rôle** : Déploiement de fichiers pièges (Canaris/Honeypot) surveillés en temps réel.
- **Détection** : Utilisation de l'Entropie de Shannon (la caractéristique la plus forte découverte par l'IA) pour une neutralisation instantanée des attaques.
- **Action** : Tue le processus malveillant (Process Killer) et génère un rapport Forensic (PDF).
- *Voir le RAPPORT_FINAL.md dans le dossier pour plus de détails.*
