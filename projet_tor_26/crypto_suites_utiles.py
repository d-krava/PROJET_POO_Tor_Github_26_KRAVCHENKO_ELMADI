import os
import hashliib

from cryptography.hazmat.primitives.asymetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
"""
CONSTANTES
"""
RSA_KEY_SIZE = 2048 #bits
AES_KEY_SIZE = 32 #octets (256 bits)
NONCE_SIZE = 12 #octets (reccomande par AES-GCM)
HKDF_info = b"onion-layer-kkey"
