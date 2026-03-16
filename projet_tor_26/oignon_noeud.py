"""
Logique crypto d'un nœud oignon : peel_layer et wrap_response.
"""
import struct
from crypto_suites_utiles import RSAKeyPair, aes_decrypt, aes_encrypt

class OnionNode:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.keypair = RSAKeyPair()
        self.public_key_pem = self.keypair.get_public_pem()
        self.session_key = None  # Pour rechiffrer réponse
    
    def peel_layer(self, packet: bytes) -> tuple:
        """
        Décrypte couche RSA → extrait next_hop + AES key + inner packet
        Returns: (next_hop_id, inner_packet_bytes)
        """
        # Décrypte couche RSA (256 premiers octets)
        rsa_layer = packet[:256]
        aes_encrypted = packet[256:]
        
        decrypted_rsa = self.keypair.decrypt_rsa(rsa_layer)
        
        # Format: [32 bytes AES key][10 bytes next_hop_id]
        aes_key = decrypted_rsa[:32]
        next_hop = decrypted_rsa[32:42].decode('utf8').strip()
        
        self.session_key = aes_key  # Sauvegarde pour réponse
        
        # Décrypte paquet interne avec AES
        inner = aes_decrypt(aes_key, aes_encrypted)
        
        return next_hop, inner
    
    def wrap_response(self, response: bytes) -> bytes:
        """Rechiffre réponse avec même clé AES session"""
        return aes_encrypt(self.session_key, response)
