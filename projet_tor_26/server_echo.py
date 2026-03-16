"""
Logique métier du serveur d'écho : renvoie ce qu'il reçoit.
"""
class EchoServer:
    def __init__(self, name: str):
        self.name = name
    
    def handle(self, message: bytes) -> bytes:
        """Traite le message (echo simple)"""
        print(f"  [{self.name}] Message reçu : {message.decode('utf8', errors='ignore')}")
        return message  # ECHO
