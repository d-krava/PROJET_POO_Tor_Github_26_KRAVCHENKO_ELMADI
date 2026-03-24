"""
socket_transport.py

Fonctions bas niveau pour envoyer et recevoir des sequences binaires
de longueur variable sur une socket TCP IPv4.

Protocole de cadrage : longueur (4 octets big-endian) || données

"""

import socket
import struct

HOST        = "127.0.0.1"
BUFFER_SIZE = 4096
LENGTH_SIZE = 4          # octets pour encoder la longueur du message


def send_seq_binaire(sock: socket.socket, data: bytes) -> None:
    """
    Envoie une sequence binaire sur une socket avec gestion de la longueur.

    Structure envoyée :
        [4B big-endian : longueur] [données]

    """
   
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)

def recv_seq_binaire(sock: socket.socket) -> bytes:
    """
    Reçoit une sequence binaire envoyée par send_seq_binaire().

    Lit d'abord les 4 octets d'en-tête pour connaître la longueur,
    puis lit exactement ce nombre d'octets.

    """
    # Lecture de l'en-tête (longueur)
    header = _recv_exactly(sock, LENGTH_SIZE)
    length = struct.unpack(">I", header)[0]

    # Lecture de la payload
    return _recv_exactly(sock, length)

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Lit exactement n octets depuis la socket.

    recv() peut retourner moins que demandé (fragmentation TCP),
    d'où la boucle tant que.

    """
    buffer = b""
    while len(buffer) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(buffer)))
        if not chunk:
            raise ConnectionError("Connexion fermée prématurément.")
        buffer += chunk
    return buffer

def send_recv(host: str, port: int, data: bytes) -> bytes:
    """
    Ouvre une connexion TCP, envoie data, attend la réponse, ferme.

    Fonction utilisée par chaque nœud (relais Tor) pour parler
    au nœud suivant (ou au serveur final).

    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        send_seq_binaire(sock, data)
        return recv_seq_binaire(sock)


