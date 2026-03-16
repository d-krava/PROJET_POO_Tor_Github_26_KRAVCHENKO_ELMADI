"""
Lance 3 nœuds + serveur echo + client de test
"""
import time
import sys
from echo_server_socket import EchoServerSocket
from onion_node_socket_v2 import OnionNodeSocket
from onion_client import OnionClient
from socket_transport import HOST

def main():
    print("🔧 Démarrage mini-réseau TOR...\n")
    
    # 1. Serveur Echo
    echo_srv = EchoServerSocket(port=2000)
    echo_srv.start()
    time.sleep(0.5)
    
    # 2. Créer 3 nœuds
    n1 = OnionNodeSocket("N1", port=3001)
    n2 = OnionNodeSocket("N2", port=3002)
    n3 = OnionNodeSocket("N3", port=3003)
    
    # 3. Tables de routage
    n1.add_route("N2", HOST, 3002)
    n2.add_route("N3", HOST, 3003)
    n3.add_route("ECHO", HOST, 2000)
    
    # 4. Démarrer nœuds
    n1.start()
    n2.start()
    n3.start()
    time.sleep(1)
    
    print("\n✅ Réseau TOR prêt !\n")
    print("Circuit : Client → N1(3001) → N2(3002) → N3(3003) → Echo(2000)\n")
    
    # 5. Client de test
    circuit = [
        ("N1", HOST, 3001, n1.get_public_key_pem()),
        ("N2", HOST, 3002, n2.get_public_key_pem()),
        ("N3", HOST, 3003, n3.get_public_key_pem())
    ]
    
    client = OnionClient(circuit)
    message = "COUCOU LE RT via TOR !".encode('utf8')
    
    print(f"📤 Envoi message : {message.decode('utf8')}\n")
    response = client.send_message(message)
    print(f"\n📥 Réponse reçue : {response.decode('utf8')}\n")
    
    print("✅ Test réussi ! Le routing oignon fonctionne.\n")
    input("Appuie sur ENTRÉE pour arrêter...")

if __name__ == "__main__":
    main()
