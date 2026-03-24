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

    def __init__(self, hote="à compléter", port=à compléter, nom_serveur="ServeurEcho"):
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
            "tag"              : base64.b64encode(tag).decode(),
            "message_chiffre"  : base64.b64encode(message_chiffre).decode(),
        }).encode("utf-8")

   # 5. Connexion et envoi 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._hote, self._port))
        sock.sendall(paquet)

        # Signale la fin de l'envoi au serveur (demi-fermeture)
        sock.shutdown(socket.SHUT_WR)

   # 6. Réception de la réponse
        reponse_brute = self._recevoir_tout(sock)
        sock.close()

        if not reponse_brute:
            print("[Client] Aucune réponse reçue.")
            return

   # 7. Déchiffrement de la réponse 
        # Cas spécial : le serveur peut envoyer du texte brut (ex. "Au revoir !")
        try:
            paquet_rep = json.loads(reponse_brute.decode("utf-8"))
            texte_rep  = self._dechiffrer_reponse(paquet_rep, cle_aes)
        except (json.JSONDecodeError, KeyError):
            # Le serveur a renvoyé un message texte brut (QUIT)
            texte_rep = reponse_brute.decode("utf-8")

        print(f"[Client] Réponse du serveur : « {texte_rep} »")

    
    def _dechiffrer_reponse(self, paquet):
        """
        Déchiffre la réponse JSON du serveur.

        Le serveur chiffre sa réponse avec une clé AES éphémère qu'il
        inclut dans le paquet (pas de chiffrement RSA de retour ici). 
        La clé AES de la réponse est incluse en clair dans le JSON (scénario simplifié).
        """
        cle_aes_rep     = base64.b64decode(paquet["cle_aes_chiffree"])
        iv_rep          = base64.b64decode(paquet["iv"])
        tag_rep         = base64.b64decode(paquet["tag"])
        message_chiffre = base64.b64decode(paquet["message_chiffre"])

        dechiffreur = Cipher(
            algorithms.AES(cle_aes_rep),
            modes.GCM(iv_rep, tag_rep),
            backend=default_backend()
        ).decryptor()

        message_clair = dechiffreur.update(message_chiffre) + dechiffreur.finalize()
        return message_clair.decode("utf-8")

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

    client = Client(hote="à compléter", port=à compléter, nom_serveur="ServeurEcho")

    # Liste de messages de démonstration
    messages = [
        "Bonjour serveur !",
        "Le chiffrement RSA protège la clé AES.",
        "AES-GCM assure confidentialité ET intégrité.",
        "QUIT",          # provoque l'arrêt du serveur
    ]

    for msg in messages:
        client.envoyer(msg)
