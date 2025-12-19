# 🔍 Port Scanner - Bash Network Security Tool

<div align="center">

![Bash](https://img.shields.io/badge/Bash-4.0%2B-green?style=for-the-badge&logo=gnu-bash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge)

**Un scanner de ports TCP léger et efficace écrit entièrement en Bash.**

[Fonctionnalités](#-fonctionnalités) •
[Installation](#-installation) •
[Utilisation](#-utilisation) •
[Exemples](#-exemples) •
[Auteur](#-auteur)

</div>

---

## 📋 Description

**Port Scanner** est un outil en ligne de commande qui permet de vérifier rapidement si des ports TCP sont ouverts sur une machine cible. Développé entièrement en Bash sans dépendances externes, il est idéal pour :

- 🔒 **Audit de sécurité** : Identifier les ports exposés sur vos serveurs
- 🔧 **Diagnostic réseau** : Vérifier si un service est accessible
- 📊 **Inventaire** : Documenter les services actifs sur votre infrastructure

## ✨ Fonctionnalités

- ✅ Scan de ports individuels ou par plage
- ✅ Détection automatique des services courants (SSH, HTTP, MySQL, etc.)
- ✅ Mode verbose pour le débogage
- ✅ Export des résultats dans un fichier
- ✅ Timeout configurable pour les scans rapides
- ✅ Interface colorée et intuitive
- ✅ Barre de progression pour les longs scans
- ✅ Gestion robuste des erreurs

## 📦 Prérequis

| Dépendance | Version | Utilisation |
|------------|---------|-------------|
| `bash` | 4.0+ | Interpréteur principal |
| `timeout` | (coreutils) | Gestion des délais de connexion |

> **Note** : Ces outils sont préinstallés sur la plupart des distributions Linux et macOS.

### Vérification des prérequis

```bash
# Vérifier la version de Bash
bash --version

# Vérifier que timeout est disponible
which timeout
```

## 🚀 Installation

### Option 1 : Cloner le dépôt (recommandé)

```bash
# Cloner le projet
git clone https://github.com/RDaneel-5090/port-scanner.git

# Accéder au répertoire
cd port-scanner

# Rendre le script exécutable
chmod +x portscan.sh
```

### Option 2 : Téléchargement direct

```bash
# Télécharger le script
curl -O https://raw.githubusercontent.com/RDaneel-5090/port-scanner/main/portscan.sh

# Rendre exécutable
chmod +x portscan.sh
```

## 📖 Utilisation

### Syntaxe générale

```bash
./portscan.sh -h <host> [OPTIONS]
```

### Options disponibles

| Option | Description | Exemple |
|--------|-------------|---------|
| `-h, --host` | Hôte cible (IP ou domaine) **[REQUIS]** | `-h 192.168.1.1` |
| `-p, --ports` | Liste de ports (séparés par des virgules) | `-p 22,80,443` |
| `-r, --range` | Plage de ports à scanner | `-r 1-1000` |
| `-t, --timeout` | Délai d'attente par port (défaut: 1s) | `-t 0.5` |
| `-o, --output` | Fichier de sortie pour les résultats | `-o results.txt` |
| `-v, --verbose` | Mode verbeux (plus de détails) | `-v` |
| `-H, --help` | Afficher l'aide | `-H` |
| `-V, --version` | Afficher la version | `-V` |

## 💡 Exemples

### Scan basique de ports web

```bash
./portscan.sh -h example.com -p 80,443
```

**Sortie :**
```
  PORT     STATUT       SERVICE
  ────────────────────────────────────
  80       OPEN         (HTTP)
  443      OPEN         (HTTPS)
```

### Scan d'une plage de ports

```bash
./portscan.sh -h 192.168.1.1 -r 20-25 -v
```

### Scan rapide avec timeout réduit

```bash
./portscan.sh -h scanme.nmap.org -r 1-100 -t 0.3
```

### Scan avec export des résultats

```bash
./portscan.sh -h myserver.com -p 22,80,443,3306,5432 -o audit.txt
```

### Scan des ports de bases de données

```bash
./portscan.sh -h database.local -p 3306,5432,27017,6379
```

## 🎯 Services détectés automatiquement

Le scanner identifie automatiquement les services suivants :

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 23 | Telnet | 3306 | MySQL |
| 25 | SMTP | 3389 | RDP |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 6379 | Redis |
| 110 | POP3 | 8080 | HTTP-Proxy |
| 143 | IMAP | 27017 | MongoDB |

## 🔙 Codes de retour

| Code | Signification |
|------|---------------|
| `0` | Succès - Au moins un port ouvert trouvé |
| `1` | Erreur - Argument invalide ou problème d'exécution |
| `2` | Aucun port ouvert trouvé |

## 📁 Structure du projet

```
port-scanner/
├── portscan.sh      # Script principal
├── README.md        # Documentation (ce fichier)
├── LICENSE          # Licence MIT
└── examples/        # Exemples de sortie (optionnel)
    └── scan_results.txt
```

## ⚠️ Avertissement légal

> **Important** : Ce script est destiné à des fins éducatives et d'audit de vos propres systèmes uniquement. Scanner des ports sur des systèmes sans autorisation explicite est **illégal** dans de nombreuses juridictions. Utilisez cet outil de manière responsable et éthique.

## 🛠️ Fonctionnement technique

Le scanner utilise la fonctionnalité native de Bash `/dev/tcp` pour établir des connexions TCP :

```bash
timeout $DELAY bash -c "echo >/dev/tcp/$HOST/$PORT" 2>/dev/null
```

Cette approche présente plusieurs avantages :
- Aucune dépendance externe (pas besoin de `nmap` ou `netcat`)
- Portable sur tous les systèmes avec Bash 4+
- Léger et rapide

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche (`git checkout -b feature/amelioration`)
3. Commit vos changements (`git commit -m 'Ajout d'une fonctionnalité'`)
4. Push sur la branche (`git push origin feature/amelioration`)
5. Ouvrir une Pull Request

## 📝 License

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👤 Auteur

**RDaneel-5090**

- 🐙 GitHub: [@RDaneel-5090](https://github.com/RDaneel-5090)

---

<div align="center">

⭐ **Si ce projet vous a été utile, n'hésitez pas à lui donner une étoile !** ⭐

</div>
