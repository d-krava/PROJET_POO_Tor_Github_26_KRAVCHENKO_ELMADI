import socket
import sys

# Adresse IP du serveur (machine distante)
TCP_IP = '10.102.74.44'

# Numéro de port du serveur (conformément à l'énoncé)
TCP_PORT = 2000

# Taille maximale des données reçues (en octets)
BUFFER_SIZE = 1024

# Message à envoyer au serveur
MESSAGE_TO_SERVER = "LE MESSAGE EST : COUCOU LE RT"

try:
    # Création de la socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print("Erreur lors de la création de la socket")
    sys.exit()

try:
    # Connexion au serveur
    tcp_socket.connect((TCP_IP, TCP_PORT))
except socket.error:
    print("Erreur lors de la connexion au serveur")
    sys.exit()

try:
    # Envoi du message (encodé en UTF-8)
    tcp_socket.send(MESSAGE_TO_SERVER.encode('utf8'))
except socket.error:
    print("Erreur lors de l'envoi du message")
    sys.exit()
  
print("Message envoyé")

# Réception de la réponse
data = tcp_socket.recv(BUFFER_SIZE)

# Fermeture de la connexion
tcp_socket.close()

print("Réponse du serveur :", data.decode('utf8'))


