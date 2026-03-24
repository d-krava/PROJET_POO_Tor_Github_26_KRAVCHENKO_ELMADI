# =============================================================================
#  TOR_client_v3.py  –  Client chiffrant (RSA + AES)
#
#  Notions abordées
#  ─────────────────
#  • Socket IPv4 TCP (AF_INET / SOCK_STREAM)
#  • Chiffrement ASYMÉTRIQUE RSA-OAEP  (chiffrement de la clé AES)
#  • Chiffrement SYMÉTRIQUE AES-256-GCM (chiffrement du message)
#  • Consultation de l'annuaire + vérification du fingerprint
# =============================================================================

import socket
import json
import base64
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives             import hashes, serialization
from cryptography.hazmat.primitives.ciphers     import Cipher, algorithms, modes
from cryptography.hazmat.backends               import default_backend

from TOR_annuaire_v3 import annuaire_global


class Client:
    """
    Client TCP/IPv4 qui :
      1. Consulte l'annuaire pour obtenir la clé publique RSA du serveur.
      2. Génère une clé AES éphémère.
      3. Chiffre la clé AES avec RSA-OAEP (chiffrement asymétrique).
      4. Chiffre le message avec AES-256-GCM  (chiffrement symétrique).
      5. Envoie le tout dans un paquet JSON.
      6. Reçoit la réponse chiffrée et la déchiffre.
    """

    def __init__(self, hote="127.0.0.1", port=5000, nom_serveur="ServeurEcho"):
        self._hote        = hote
        self._port        = port
        self._nom_serveur = nom_serveur

      # Récupération de la clé publique dans l'annuaire 
        cle_pem, fingerprint = annuaire_global.obtenir_cle(nom_serveur)

        if cle_pem is None:
            raise RuntimeError(
                f"[Client] Le serveur '{nom_serveur}' est introuvable dans l'annuaire."
            )

        print(f"[Client] Clé publique récupérée pour '{nom_serveur}'")
        print(f"[Client] Fingerprint : {fingerprint[:32]}…")

      # Vérification locale du fingerprint 
        fp_calcule = hashlib.sha256(cle_pem).hexdigest()
        if fp_calcule == fingerprint:
            print("[Client] ✔  Fingerprint vérifié : clé authentique.")
        else:
            raise RuntimeError("[Client] ✘  Fingerprint invalide ! Possible attaque MITM.")

      # Chargement de la clé publique RSA 
        self._cle_publique_rsa = serialization.load_pem_public_key(
            cle_pem,
            backend=default_backend()
        )

 
    def envoyer(self, message):
        """
        Chiffre message (str), l'envoie au serveur et affiche l'écho.

        message : str – texte à envoyer (utiliser "QUIT" pour arrêter le serveur)
        """
        print(f"\n[Client] Envoi : « {message} »")

   # 1. Génération de la clé AES éphémère 
        cle_aes = os.urandom(32)          # AES-256 → 32 octets
        iv      = os.urandom(12)          # GCM recommande 96 bits

   # 2. Chiffrement du message avec AES-256-GCM 
        message_bytes = message.encode("utf-8")

        chiffreur = Cipher(
            algorithms.AES(cle_aes),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        message_chiffre = chiffreur.update(message_bytes) + chiffreur.finalize()
        tag             = chiffreur.tag                   # tag d'intégrité GCM

        print(f"[Client] Message chiffré AES ({len(message_chiffre)} octets)")

   # 3. Chiffrement de la clé AES avec RSA-OAEP 
        cle_aes_chiffree = self._cle_publique_rsa.encrypt(
            cle_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[Client] Clé AES chiffrée RSA ({len(cle_aes_chiffree)} octets)")

   # 4. Sérialisation JSON du paquet
        paquet = json.dumps({
            "cle_aes_chiffree" : base64.b64encode(cle_aes_chiffree).decode(),
            "iv"               : base64.b64encode(iv).decode(),
            "tag"              : base64.b64encode(
