"""
echo_server_socket.py
---------------------
Serveur d'écho TCP IPv4.
"""
import socket
import threading

from echo_server import EchoServer
from socket_transport import send_seq_binaire, recv_seq_binaire, HOST

class EchoServerSocket:
        
        def __init__(self, port: int) -> None:
                self.port = port
                self._inner = EchoServer("echo_server")
                self._thread = threading.Thread(
                        target=self._serve, daemon=True, name="echo-server"
                )
       
        def start(self) -> None:
                self._thread.start()
        
        def _serve(self) -> None:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        srv.bind((HOST, self.port))
                        srv.listen(8)
                        print(f" [echo_server] Écoute sur {HOST}:{self.port}")
                        while True:
                                conn, _ = srv.accept()
                                threading.Thread(
                                        target=self._handle, args=(conn,), daemon=True
                                ).start()

        def _handle(self, conn: socket.socket) -> None:
                with conn:
                        message = recv_seq_binaire(conn)
                        response = self._inner.handle(message)
                        send_seq_binaire(conn, response)
