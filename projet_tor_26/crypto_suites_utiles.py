"""
crypto_suites_utiles.py
---------------
Utilitaires cryptographiques pour le réseau en oignon.

    - Génération de paires de clés RSA (chiffrement asymétrique)
    - Chiffrement / déchiffrement RSA-OAEP
    - Chiffrement symétrique AES-GCM (couche d'oignon)
    - Dérivation de clés AES depuis un secret partagé (HKDF)
    - Hachage SHA-256 (utilisé par le serveur de clés publiques)
"""

import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Constantes
# 
RSA_KEY_SIZE   = 2048   # bits
AES_KEY_SIZE   = 32     # bytes (256 bits)
NONCE_SIZE     = 12     # bytes recommandé pour AES-GCM
HKDF_INFO      = b"onion-layer-key"


# Classe RSAKeyPair
# 
class RSAKeyPair:

    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
        )
        self._public_key = self._private_key.public_key()

    # -- Sérialisation -------------------------------------------------------

    def public_key_pem(self) -> bytes:
        """
        Retourne la clé publique au format PEM (bytes)
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_key_pem(self) -> bytes:
        """
        Retourne la clé privée au format PEM (bytes, non chiffrée)
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # -- Opérations cryptographiques -----------------------------------------

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Déchiffre avec la clé PRIVÉE (RSA-OAEP / SHA-256)
        """
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    
    def public_key(self):
        return self._public_key

    public_key = property(public_key)


# Fonctions utilitaires RSA
# 

def load_public_key(pem: bytes):
    """
    Charge une clé publique depuis son encodage PEM
    """
    return serialization.load_pem_public_key(pem)


def rsa_encrypt(public_key, texte_clair: bytes) -> bytes:
    """
    Chiffre texte_clair avec public_key (RSA-OAEP / SHA-256)
    """
    return public_key.encrypt(
        texte_clair,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# Fonctions utilitaires AES-GCM
# 

def derive_aes_key(secret: bytes) -> bytes:
    """
    Transforme n'importe quelle valeur secrète en clé AES valide via HKDF-SHA256
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(secret)


def aes_encrypt(key: bytes, texte_clair: bytes) -> bytes:
    """
    Chiffre texte_clair avec AES-256-GCM.
    Retourne : nonce (12 B) || ciphertext+tag
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, texte_clair, None)
    return nonce + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    
    nonce      = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_aes_key() -> bytes:
    """ 
    Génère une clé AES-256 aléatoire.
    """
    return os.urandom(AES_KEY_SIZE)


# Fonctions de hachage
# 

def sha256_hex(data: bytes) -> str:
    """
    Retourne le hachage SHA-256 de *data* sous forme hexadécimale 
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    Retourne le hachage SHA-256 de *data* sous forme binaire
    """
    return hashlib.sha256(data).digest()
