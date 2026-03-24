import sys
import time
import os

# Importation des classes de ton professeur
from TOR_serveur_v3 import Serveur
from TOR_client_v3 import Client
from TOR_annuaire_v3 import annuaire_global

# Configuration locale
HOTE_LOCAL = "127.0.0.1"
PORT_LOCAL = 5000
NOM_SERVEUR = "ServeurEcho"
FICHIER_CLE = f"{NOM_SERVEUR}.pem"

def lancer_serveur():
    print("=== DÉMARRAGE DU SERVEUR ===")
    # Instanciation du serveur
    serveur = Serveur(hote=HOTE_LOCAL, port=PORT_LOCAL, nom=NOM_SERVEUR)
    
    # Récupération de la clé depuis l'annuaire RAM du serveur
    cle_pem, _ = annuaire_global.obtenir_cle(NOM_SERVEUR)
    
    # Sauvegarde dans un fichier pour que le client (Terminal 2) puisse la lire
    with open(FICHIER_CLE, "wb") as f:
        f.write(cle_pem)
    print(f"[Main] Clé publique exportée dans le fichier '{FICHIER_CLE}' pour le client.")
    
    # Lancement de la boucle d'écoute
    serveur.demarrer()

def lancer_client():
    print("=== DÉMARRAGE DU CLIENT ===")
    
    # 1. Le client doit d'abord lire le fichier de clé généré par le serveur
    if not os.path.exists(FICHIER_CLE):
        print(f"[Erreur] Le fichier '{FICHIER_CLE}' n'existe pas.")
        print("         Assure-toi de lancer d'abord 'python3 main.py serveur' dans l'autre terminal !")
        sys.exit(1)
        
    with open(FICHIER_CLE, "rb") as f:
        cle_pem_recue = f.read()
        
    # 2. On injecte la clé dans l'annuaire RAM du client
    annuaire_global.enregistrer(NOM_SERVEUR, cle_pem_recue)
    print(f"[Main] Clé publique importée avec succès depuis '{FICHIER_CLE}'.\n")

    # 3. Instanciation et connexion du client
    client = Client(hote=HOTE_LOCAL, port=PORT_LOCAL, nom_serveur=NOM_SERVEUR)
    
    # 4. Envoi des messages de test
    messages = [
        "Salut, c'est un test depuis main.py !",
        "Le chiffrement a l'air de bien fonctionner.",
        "QUIT" # Ce message va demander au serveur de s'arrêter proprement
    ]
    
    for msg in messages:
        client.envoyer(msg)
        time.sleep(1.5) # Petite pause pour bien voir les logs dans les terminaux

if __name__ == "__main__":
    # Vérification des arguments passés dans la ligne de commande
    if len(sys.argv) != 2 or sys.argv[1] not in ["serveur", "client"]:
        print("Utilisation incorrecte.")
        print("  -> Pour lancer le serveur : python3 main.py serveur")
        print("  -> Pour lancer le client  : python3 main.py client")
        sys.exit(1)
        
    # Lancement en fonction de l'argument
    if sys.argv[1] == "serveur":
        lancer_serveur()
    elif sys.argv[1] == "client":
        lancer_client()
