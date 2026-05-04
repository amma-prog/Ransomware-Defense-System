# 🛡 RansomwareDetector — Détection Précoce par Canary \& Entropie

Système de détection précoce de ransomware basé sur trois piliers :
fichiers leurres (Canary), analyse d'entropie de Shannon, et IA comportementale.

\---

## 📐 Architecture

```
ransomware\\\_detector/
├── main.py                        ← Point d'entrée \\\& orchestrateur
├── config.py                      ← Configuration centralisée
├── requirements.txt
│
├── canary/
│   └── canary\\\_manager.py          ← Création/gestion des fichiers appâts
│
├── analysis/
│   ├── entropy.py                 ← Calcul entropie de Shannon
│   ├── features.py                ← Extraction vecteur ML (9 features)
│   └── ml\\\_model.py                ← Random Forest + Isolation Forest
│
├── monitor/
│   └── watcher.py                 ← Surveillance Watchdog multi-répertoires
│
├── response/
│   ├── killer.py                  ← Identification \\\& kill processus suspects
│   └── alerting.py                ← Alertes (console, email, webhook)
│
├── models/
│   └── detector.pkl               ← Modèle ML sérialisé (généré au 1er run)
│
├── logs/
│   ├── app.log                    ← Logs applicatifs
│   └── forensics.json             ← Rapport forensique JSON
│
├── test\\\_attaque.py                ← Script de simulation d'attaque (Test)
└── tests/
    └── test\\\_entropy.py            ← Tests unitaires mathématiques
```

\---

## 🔬 Principe de Fonctionnement

### 1\. Canary Files 🪤

Des fichiers leurres imitant des cibles à haute valeur
(`passwords\\\_backup.txt`, `financial\\\_report\\\_2024.xlsx`, `private\\\_keys.pem`…)
sont déployés dans les répertoires sensibles. Leur entropie baseline est
enregistrée au déploiement.

### 2\. Entropie de Shannon 📊

```
H = -Σ p(x) · log₂(p(x))
```

|Valeur|Type de fichier|
|-|-|
|0.0 – 3.0|Texte brut|
|3.0 – 6.0|Documents normaux ✅|
|6.0 – 7.2|Compressé ⚠️|
|7.2 – 8.0|Chiffré / Ransomware 🚨|

### 3\. Modèle IA 🧠

Deux algorithmes en ensemble :

* **Random Forest** (supervisé) → patterns connus
* **Isolation Forest** (non-supervisé) → anomalies comportementales / zero-day

9 features extraites par événement :
`entropy\\\_value`, `entropy\\\_delta`, `modification\\\_rate`,
`extension\\\_changed`, `size\\\_ratio`, `time\\\_of\\\_day`,
`process\\\_reputation`, `files\\\_renamed\\\_count`, `shadow\\\_copy\\\_access`

\---

## 🚀 Installation

```bash
# Cloner le projet
git clone <repo>
cd ransomware\\\_detector

# Installer les dépendances
pip install -r requirements.txt

# Démarrer (entraîne le modèle automatiquement au 1er lancement)
python main.py
```

\---

## 💻 Utilisation

```bash
# Démarrage normal
python main.py

# Forcer le ré-entraînement du modèle ML
python main.py --train

# Voir l'état des canary files (entropie live)
python main.py --status

# Supprimer tous les canary files
python main.py --cleanup
```

\---

## ⚙️ Configuration

Éditer `config.py` pour personnaliser :

```python
ENTROPY\\\_CRITICAL   = 7.2    # Seuil d'alerte entropique
AUTO\\\_KILL          = True   # Kill automatique du processus suspect
CANARY\\\_COUNT       = 20     # Nombre de fichiers leurres
ALERT\\\_EMAIL\\\_ENABLED = False  # Activer les alertes email
```

\---

## 🧪 Tests \& Simulation

### 1\. Simulation d'Attaque (Réel)

Pour tester le comportement du système face à une menace, lancez le script de simulation :

```bash
python test\_attaque.py
```

*Le script va cibler un fichier canari sur le bureau et tenter de le chiffrer. Le moteur ML doit détecter l'anomalie et stopper le processus.*

### 2\. Tests Unitaires

Pour vérifier la précision des calculs mathématiques (Entropie) :

```bash
pytest tests/ -v
```

\---

## 📊 Pipeline de Détection

```
Fichier Canary Modifié
        │
        ▼
  Calcul Entropie  ──── Entropie > 7.2 ? ────► ALERTE CRITIQUE
        │
        ▼
 Extraction Features (9 features)
        │
        ▼
  Modèle ML (RF + IF)
        │
        ├── NORMAL    → Log + surveillance continue
        │
        └── RANSOMWARE → Alerte + Snapshot forensique + Kill process
```

\---

## 🛡 Niveaux d'Alerte

|Niveau|Déclencheur|Action|
|-|-|-|
|INFO|Modification mineure|Log uniquement|
|WARNING|Delta entropie > 1.0 bits|Surveillance accrue|
|CRITICAL|Canary touché, entropie > 7.2|Kill automatique|
|EMERGENCY|> 50 fichiers/min ou extension .locked|Isolation réseau|

\---

## 📝 Logs Forensiques

Chaque incident génère un rapport JSON dans `logs/forensics.json` :

```json
{
  "timestamp": "2024-01-15T03:42:17",
  "trigger\\\_file": "/home/user/Documents/passwords\\\_backup.txt",
  "processes\\\_killed": 1,
  "snapshots": \\\[{
    "pid": 4821,
    "name": "suspicious.exe",
    "cmdline": \\\["suspicious.exe", "--encrypt"],
    "open\\\_files": \\\[...],
    "connections": \\\[...]
  }]
}
```

