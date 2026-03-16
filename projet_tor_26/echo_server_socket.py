import socket
import sys

TCP_IP_srv = '10.102.74.44'
TCP_PORT = 2000
BUFFER_SIZE = 1024


try :
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
        print('Une error')
        sys.exit();

tcp_socket.bind((TCP_IP_srv, TCP_PORT))

tcp_socket.listen(3)
print('En ecoute')

connexion, adresse = tcp_socket.accept()
print('Connecté avec : ', adresse)
data = connexion.recv(BUFFER_SIZE)
print('Message reçu du client : ', data)

reponse_serveur = 'Merci pour la connexion'
connexion.sendall(reponse_serveur.encode('utf8'))

connexion.close()
