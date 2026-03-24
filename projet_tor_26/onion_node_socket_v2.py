"""
onion_node_socket.py

OnionNode communiquant via des sockets TCP IPv4

Chaque nœud :
    - écoute sur un port TCP (thread serveur)
    - traite le paquet reçu (peel_layer)
    - transmet au nœud suivant via send_recv()
    - rechiffre la réponse et la renvoie au client
"""

import struct
import threading
import socket

from crypto_suites_utiles import RSAKeyPair, aes_decrypt, aes_encrypt
from socket_transport  import send_seq_binaire, recv_seq_binaire, send_recv, HOST


class OnionNodeSocket:
    """
    Nœud Tor communiquant via sockets TCP IPv4.

    Attributs :
        node_id  : identifiant du nœud
        port     : port d'écoute TCP
        table_routage : dict {next_hop_id → (host, port)}
    """

    def __init__(self, node_id: str, port: int) -> None:
        self.node_id       = node_id
        self.port          = port
        self._inner        = OnionNode(node_id)    # logique crypto inchangée
        self._table_routage: dict = {}             # remplie avant démarrage
        self._server_thread = threading.Thread(
            target=self._serve,
            daemon=True,
            name=f"server-{node_id}",
        )

    
    def get_public_key_pem(self) -> bytes:
        return self._inner.public_key_pem

    def add_route(self, next_hop_id: str, host: str, port: int) -> None:
        """Enregistre l'adresse TCP du prochain saut."""
        self._table_routage[next_hop_id] = (host, port)

    def start(self) -> None:
        """Démarre le thread serveur TCP."""
        self._server_thread.start()

    #   Serveur TCP

    def _serve(self) -> None:
        """
        Boucle d'écoute TCP.
        Accepte une connexion, la traite dans un thread dédié

        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, self.port))
            srv.listen(8)
            print(f"  [{self.node_id}] Écoute sur {HOST}:{self.port}")

            while True:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                )
                t.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        """
        Traite une connexion entrante : peel → forward → wrap → réponse
        """
        with conn:
            packet   = recv_seq_binaire(conn)
            response = self._process(packet)
            send_seq_binaire(conn, response)


    def _process(self, packet: bytes) -> bytes:
        """
        Pèle la couche, transmet au saut suivant via socket,
        rechiffre la réponse.

        """
        print(f"  [{self.node_id}] Paquet reçu ({len(packet)} octets)")

        next_hop, inner = self._inner.peel_layer(packet)

        print(f"  [{self.node_id}] Prochain saut : '{next_hop}'")

        host, port    = self._table_routage[next_hop]
        response      = send_recv(host, port, inner)   # ← SOCKET IPv4
       
        wrapped = self._inner.wrap_response(response)
        print(f"  [{self.node_id}] Réponse rechiffrée ({len(wrapped)} octets)")
        return wrapped


