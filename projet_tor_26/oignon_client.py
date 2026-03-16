"""
Client qui construit un paquet oignon multi-couches et l'envoie au premier nœud.
"""
import socket
import os
from socket_transport import send_seq_binaire, recv_seq_binaire, HOST
from crypto_suites_utiles import encrypt_rsa, aes_encrypt, aes_decrypt

class OnionClient:
    def __init__(self, circuit: list):
        """
        circuit = [(node_id, host, port, public_key_pem), ...]
        Exemple: [('N1', '127.0.0.1', 3001, pubkey1), ...]
        """
        self.circuit = circuit
        self.session_keys = []
    
    def send_message(self, message: bytes) -> bytes:
        """Construit oignon, envoie, reçoit réponse"""
        # Construire oignon de l'intérieur vers l'extérieur
        packet = message
        self.session_keys = []
        
        # Inverse le circuit pour chiffrer couche par couche
        for i in range(len(self.circuit) - 1, -1, -1):
            node_id, host, port, pubkey_pem = self.circuit[i]
            
            # Génère clé AES pour cette couche
            aes_key = os.urandom(32)
            self.session_keys.insert(0, aes_key)
            
            # Chiffre paquet avec AES
            aes_encrypted = aes_encrypt(aes_key, packet)
            
            # Next hop (ou "ECHO" pour dernier)
            if i == len(self.circuit) - 1:
                next_hop = "ECHO".ljust(10, ' ')
            else:
                next_hop = self.circuit[i+1][0].ljust(10, ' ')
            
            # Couche RSA : [AES key 32B][next_hop 10B]
            rsa_payload = aes_key + next_hop.encode('utf8')
            rsa_encrypted = encrypt_rsa(pubkey_pem, rsa_payload)
            
            # Paquet final = [RSA layer][AES encrypted]
            packet = rsa_encrypted + aes_encrypted
        
        # Envoie au premier nœud
        entry_node = self.circuit[0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((entry_node[1], entry_node[2]))
            send_seq_binaire(s, packet)
            encrypted_response = recv_seq_binaire(s)
        
        # Décrypte réponse couche par couche
        response = encrypted_response
        for aes_key in self.session_keys:
            response = aes_decrypt(aes_key, response)
        
        return response
