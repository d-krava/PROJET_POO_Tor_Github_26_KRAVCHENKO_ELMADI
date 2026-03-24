# =============================================================================
#  serveur.py  –  Serveur écho chiffré (RSA + AES)
#
#  • Socket IPv4 TCP (AF_INET / SOCK_STREAM)
#  • Chiffrement ASYMÉTRIQUE RSA-OAEP  (déchiffrement côté serveur)
#  • Chiffrement SYMÉTRIQUE AES-256-GCM (pour la réponse)
# =============================================================================

import socket
import json
import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives               import hashes, serialization
from cryptography.hazmat.primitives.ciphers       import Cipher, algorithms, modes
from cryptography.hazmat.backends                 import default_backend

from TOR_annuaire_v3 import annuaire_global


class Serveur:
    """
    Serveur écho TCP/IPv4.

    Flux d'un échange
    ─────────────────
    1. Le client envoie un paquet JSON :
       {
         "cle_aes_chiffree" : <base64>,   ← clé AES chiffrée avec la clé publique RSA
         "iv"               : <base64>,   ← vecteur d'initialisation AES-GCM
         "tag"              : <base64>,   ← tag d'authentification AES-GCM
         "message_chiffre"  : <base64>    ← message chiffré avec AES
       }
    2. Le serveur déchiffre la clé AES (RSA-OAEP) puis le message (AES-GCM).
    3. Le serveur renvoie le même message en clair (écho) chiffré avec AES.

    """

    def __init__(self, hote="127.0.0.1", port=5000, nom="ServeurEcho"):
        self._hote  = hote
        self._port  = port
        self._nom   = nom

      # Génération de la paire de clés RSA
        print(f"[{self._nom}] Génération de la paire RSA 2048 bits…")
        self._cle_privee = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._cle_publique = self._cle_privee.public_key()

      # Sérialisation PEM de la clé publique ─
        self._cle_publique_pem = self._cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

      # Publication dans l'annuaire
        annuaire_global.enregistrer(self._nom, self._cle_publique_pem)

      # Socket TCP / IPv4
        self._socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def demarrer(self):
        self._socket_serveur.bind((self._hote, self._port))
        self._socket_serveur.listen(5)
        print(f"[{self._nom}] En écoute sur {self._hote}:{self._port}")

        continuer = True         
        while continuer:
            print(f"\n[{self._nom}] En attente d'un client…")
            socket_client, adresse = self._socket_serveur.accept()
            print(f"[{self._nom}] Connexion de {adresse}")

            continuer = self._traiter_client(socket_client)

        self._socket_serveur.close()
        print(f"[{self._nom}] Arrêté.")

    def _traiter_client(self, socket_client):
        """
        Reçoit un paquet JSON, le déchiffre, renvoie l'écho chiffré.
        Retourne True  → continuer à écouter
                 False → arrêter le serveur (le client envoie "QUIT")
        """
        donnees_brutes = self._recevoir_tout(socket_client)

        if not donnees_brutes:
            socket_client.close()
            return True                    

   # 1. Désérialisation JSON
        paquet = json.loads(donnees_brutes.decode("utf-8"))

        cle_aes_chiffree = base64.b64decode(paquet["cle_aes_chiffree"])
        iv               = base64.b64decode(paquet["iv"])
        tag              = base64.b64decode(paquet["tag"])
        message_chiffre  = base64.b64decode(paquet["message_chiffre"])

   # 2. Déchiffrement de la clé AES avec RSA-OAEP 
        cle_aes = self._cle_privee.decrypt(
            cle_aes_chiffree,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[{self._nom}] Clé AES déchiffrée ({len(cle_aes)*8} bits)")

   # 3. Déchiffrement du message avec AES-256-GCM 
        dechiffreur = Cipher(
            algorithms.AES(cle_aes),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        message_clair = dechiffreur.update(message_chiffre) + dechiffreur.finalize()
        texte = message_clair.decode("utf-8")
        print(f"[{self._nom}] Message reçu : « {texte} »")

   # 4. Décision QUIT 
        if texte.strip().upper() == "QUIT":
            socket_client.sendall(b"Au revoir !")
            socket_client.close()
            return False               # signale l'arrêt du serveur

   # 5. Écho chiffré avec une NOUVELLE clé AES éphémère
        reponse        = f"ECHO : {texte}"
        reponse_chiffree, iv_rep, tag_rep, cle_aes_rep = self._chiffrer_aes(
            reponse.encode("utf-8")
        )

        paquet_reponse = json.dumps({
            "cle_aes_chiffree" : base64.b64encode(cle_aes_rep).decode(),
            "iv"               : base64.b64encode(iv_rep).decode(),
            "tag"              : base64.b64encode(tag_rep).decode(),
            "message_chiffre"  : base64.b64encode(reponse_chiffree).decode(),
        }).encode("utf-8")

        socket_client.sendall(paquet_reponse)
        socket_client.close()
        return True

    def _chiffrer_aes(self, texte_bytes):
        """
        Chiffre texte_bytes avec AES-256-GCM.
        Retourne (chiffré, iv, tag, clé_aes).
        La clé AES est générée aléatoirement (clé éphémère).
        """
        cle_aes = os.urandom(32)          # 256 bits
        iv      = os.urandom(12)          # 96 bits recommandé pour GCM

        chiffreur = Cipher(
            algorithms.AES(cle_aes),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        chiffre = chiffreur.update(texte_bytes) + chiffreur.finalize()
        return chiffre, iv, chiffreur.tag, cle_aes

    def _recevoir_tout(self, sock, taille_tampon=4096):
        """
        Lit tous les octets disponibles sur la socket.
        """
        fragments = []
        sock.settimeout(2.0)

        continuer = True
        while continuer:
            try:
                morceau = sock.recv(taille_tampon)
                if len(morceau) == 0:
                    continuer = False
                else:
                    fragments.append(morceau)
            except socket.timeout:
                continuer = False          

        return b"".join(fragments)



if __name__ == "__main__":
    serveur = Serveur(hote="127.0.0.1", port=5000, nom="ServeurEcho")
    serveur.demarrer()
