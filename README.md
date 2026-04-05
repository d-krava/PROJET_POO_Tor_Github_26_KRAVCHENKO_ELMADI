# 🧅 Mini Réseau Tor en Python

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Crypto](https://img.shields.io/badge/Crypto-RSA%20%2B%20AES--GCM-purple)
![Projet](https://img.shields.io/badge/Projet-BUT%20R%26T-green)
![Commits](https://img.shields.io/badge/Commits-Sign%C3%A9s%20GPG-orange)

## Description

Ce projet est une simulation pédagogique d’un mini réseau Tor réalisée en Python.

L’objectif est de comprendre :
- le transport TCP avec sockets ;
- le chiffrement asymétrique RSA ;
- le chiffrement symétrique AES-GCM ;
- la gestion d’un annuaire de clés publiques ;
- le principe du routage en oignon.

Le client chiffre un message avant l’envoi, le serveur le déchiffre, puis renvoie une réponse chiffrée.  
Le projet propose aussi une interface graphique pour faciliter les tests.

## Objectif pédagogique

Le but de ce projet est de reproduire, à petite échelle, certaines idées du réseau Tor :

- isolation entre client et serveur ;
- utilisation de clés publiques ;
- chiffrement des échanges ;
- observation des paquets réseau avec Wireshark ;
- compréhension du rôle des différentes couches réseau et applicatives.

## Fonctionnement général

Le fonctionnement global est le suivant :

1. Le serveur génère une paire de clés RSA.
2. La clé publique du serveur est enregistrée dans un annuaire.
3. Le client récupère cette clé publique.
4. Le client génère une clé AES temporaire.
5. Le message est chiffré avec AES-GCM.
6. La clé AES est elle-même chiffrée avec la clé publique RSA du serveur.
7. Le client envoie un paquet JSON contenant :
   - la clé AES chiffrée ;
   - le vecteur d’initialisation ;
   - le tag d’authentification ;
   - le message chiffré.
8. Le serveur déchiffre la clé AES, puis le message.
9. Le serveur renvoie une réponse chiffrée au client.

## Architecture simplifiée

```text
[ Client ]
    |
    |  message chiffré (RSA + AES-GCM)
    v
[ Serveur ]
    |
    |  réponse chiffrée
    v
[ Client ]
```

Version logique du projet élargi :

```text
[ GUI Client ] ---> [ TOR_client_v3.py ] ---> [ socket TCP ] ---> [ TOR_serveur_v3.py ] ---> [ GUI Serveur ]
                             |
                             v
                    [ Annuaire de clés ]
```

## Fichiers du projet

### Fichiers principaux

- `main.py` : point d’entrée simple pour lancer le client ou le serveur en ligne de commande.
- `gui_client.py` : interface graphique du client.
- `gui_serveur.py` : interface graphique du serveur.

### Logique réseau et crypto

- `TOR_client_v3.py` : logique du client, chiffrement et envoi.
- `TOR_serveur_v3.py` : logique du serveur, réception et déchiffrement.
- `socket_transport.py` : fonctions bas niveau pour envoyer et recevoir les données sur socket TCP.
- `echo_server_socket_v2.py` : serveur d’écho TCP.
- `onion_node_socket_v2.py` : nœud de type onion relay.

### Gestion des clés

- `TOR_annuaire_v3.py` : annuaire simplifié des clés publiques.
- `annuaire_cles.py` : structure plus complète de gestion de l’annuaire.
- `crypto_suites_utiles.py` : utilitaires de chiffrement (RSA, AES-GCM, HKDF, SHA-256).

## Technologies utilisées

- Python 3
- Tkinter
- Sockets TCP IPv4
- RSA-OAEP
- AES-256-GCM
- SHA-256
- Wireshark
- Git / GitHub

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/TON-UTILISATEUR/TON-REPO.git
cd TON-REPO
```

### 2. Installer les dépendances

```bash
pip install -r requirements.txt
```

> Si `requirements.txt` n’existe pas encore, créer un fichier contenant :

```txt
cryptography>=41.0.0
```

## Lancement du projet

### Mode interface graphique

Lancer le serveur dans un premier terminal :

```bash
python3 gui_serveur.py
```

Puis lancer le client dans un second terminal :

```bash
python3 gui_client.py
```

### Mode ligne de commande

Lancer le serveur :

```bash
python3 main.py serveur
```

Puis lancer le client :

```bash
python3 main.py client
```

## Utilisation

### Côté serveur

1. Lancer `gui_serveur.py`
2. Vérifier le port
3. Démarrer le serveur
4. Le serveur génère et exporte la clé publique `.pem`

### Côté client

1. Lancer `gui_client.py`
2. Charger la clé publique `.pem`
3. Saisir l’adresse IP et le port du serveur
4. Écrire un message
5. Cliquer sur **Envoyer**

## Sécurité mise en œuvre

Le projet utilise deux mécanismes complémentaires :

- **RSA-OAEP** pour chiffrer la clé AES ;
- **AES-256-GCM** pour chiffrer le message et garantir son intégrité.

Cela permet de :
- protéger le contenu du message ;
- éviter l’envoi du message en clair ;
- vérifier que les données n’ont pas été modifiées.

## Analyse Wireshark

Les captures Wireshark montrent que les échanges transitent sous forme chiffrée dans les paquets TCP.

On observe notamment :
- le **3-way handshake** TCP ;
- un paquet **PSH, ACK** du client vers le serveur contenant les données chiffrées ;
- un paquet **PSH, ACK** du serveur vers le client contenant la réponse chiffrée ;
- la fermeture propre de la connexion avec **FIN, ACK**.

Les données visibles dans Wireshark ne sont pas le message en clair, mais un JSON contenant :
- `cle_aes_chiffree`
- `iv`
- `tag`
- `message_chiffre`

## Captures d’écran

### Handshake TCP

![Handshake TCP](docs/images/wireshark-handshake.png)

### Envoi du message chiffré

![Envoi chiffré](docs/images/wireshark-envoi-chiffre.png)

### Réponse chiffrée du serveur

![Réponse chiffrée](docs/images/wireshark-reponse-chiffree.png)

## Exemple de paquet observé

Exemple logique du contenu applicatif envoyé :

```json
{
  "cle_aes_chiffree": "...",
  "iv": "...",
  "tag": "...",
  "message_chiffre": "..."
}
```

## Résultat obtenu

Le projet permet de démontrer que :

- le client et le serveur communiquent correctement ;
- les données ne circulent pas en clair sur le réseau ;
- l’utilisation combinée de RSA et AES fonctionne ;
- les échanges sont observables dans Wireshark ;
- l’interface graphique simplifie les tests.

## Commits signés

Les commits du projet sont signés avec une clé GPG afin de garantir l’authenticité de l’auteur.

Vérification locale :

```bash
git log --show-signature
```

## Auteurs

Projet réalisé par :

bibo302 = Omar El Madi  
d-krava = Dmytro Kravchenko

## Améliorations possibles

- ajouter plusieurs vrais nœuds onion en chaîne ;
- automatiser la distribution des clés ;
- améliorer l’interface graphique ;
- journaliser les événements dans des fichiers ;
- ajouter davantage de vérifications et de gestion d’erreurs.

## Licence

Projet académique réalisé dans le cadre d’un cours de réseaux / cybersécurité.

