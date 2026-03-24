"""
annuaire_cles.py
----------------
Serveur d'annuaire de clés publiques.

Rôle :
    - Stocker la clé publique de chaque nœud du réseau.
    - Associer à chaque clé publique son empreinte (hash SHA-256).
    - Permettre au client de récupérer les clés publiques des nœuds
      pour construire le circuit chiffré en oignon.

Concept :
    - Le hachage SHA-256 sert d'empreinte (fingerprint) fiable pour
      identifier et vérifier une clé publique sans la transmettre en clair
      à chaque fois.
    
"""

from __future__ import annotations

from typing import Dict, List, Optional
from dataclasses import dataclass, field

from crypto_suites_utiles import sha256_hex


# ---------------------------------------------------------------------------
# Structure de données : entrée d'annuaire
# ---------------------------------------------------------------------------

@dataclass
class DirectoryEntry:
    """
    Représente l'enregistrement d'un nœud dans l'annuaire
    """
    def __init__(self, node_id: str, public_key_pem: bytes) -> None:
        self.node_id         = node_id
        self.public_key_pem  = public_key_pem
        self.fingerprint     = sha256_hex(self.public_key_pem)  # calculé automatiquement

    def __repr__(self) -> str:
        return (
            f"DirectoryEntry("
            f"node_id={self.node_id!r}, "
            f"public_key_pem={self.public_key_pem[:20]!r}..., "
            f"fingerprint={self.fingerprint!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DirectoryEntry):
            return NotImplemented
        return (
            self.node_id        == other.node_id
            and self.public_key_pem == other.public_key_pem
            and self.fingerprint    == other.fingerprint
        )

    def summary(self) -> str:
        """
        Retourne un résumé lisible de l'entrée
        """
        short_fp = self.fingerprint[:16] + "..."
        return f"[{self.node_id}] fingerprint={short_fp}"


# Classe principale : KeyDirectoryServer
# 

class KeyDirectoryServer:
    """
    Annuaire centralisé des clés publiques des nœuds Tor
    """

    def __init__(self) -> None:
        # Dictionnaire node_id -> DirectoryEntry
        self._entries: Dict[str, DirectoryEntry] = {}

    # -- Enregistrement ------------------------------------------------------

    def register(self, node_id: str, public_key_pem: bytes) -> DirectoryEntry:
        """
        Enregistre un nœud avec sa clé publique.

        Arguments:
            node_id        : Identifiant unique du nœud.
            public_key_pem : Clé publique RSA encodée PEM.

        Retours:
            L'entrée d'annuaire créée (avec son fingerprint).

        Raises:
            ValueError : Si le node_id est déjà enregistré.
        """
        if node_id in self._entries:
            raise ValueError(f"Le nœud '{node_id}' est déjà enregistré.")

        entry = DirectoryEntry(node_id=node_id, public_key_pem=public_key_pem)
        self._entries[node_id] = entry
        return entry

    # -- Consultation --------------------------------------------------------

    def get_entry(self, node_id: str) -> Optional[DirectoryEntry]:
        """
        Retourne l'entrée d'un nœud ou None s'il est inconnu
        """
        return self._entries.get(node_id)

    def get_public_key_pem(self, node_id: str) -> bytes:
        """
        Retourne la clé publique PEM d'un nœud.

        Raises:
            KeyError : Si le nœud est inconnu.
        """
        
        entry = self._entries.get(node_id)
        if entry is None:
            raise KeyError(f"Nœud inconnu : '{node_id}'")
        return entry.public_key_pem

    def get_fingerprint(self, node_id: str) -> str:
        """
        Retourne le fingerprint SHA-256 de la clé publique d'un nœud.

        Raises:
            KeyError : Si le nœud est inconnu.
        """
        entry = self._entries.get(node_id)
        if entry is None:
            raise KeyError(f"Nœud inconnu : '{node_id}'")
        return entry.fingerprint

    def verify_fingerprint(self, node_id: str, pem: bytes) -> bool:
        """
        Vérifie que la clé publique PEM correspond bien au fingerprint
        enregistré pour node_id.

        Utile pour détecter une tentative d'usurpation (man-in-the-middle).
        """
        registered_fp = self.get_fingerprint(node_id)
        candidate_fp  = sha256_hex(pem)
        return registered_fp == candidate_fp

    def list_nodes(self) -> List[str]:
        """
        Retourne la liste des identifiants de nœuds enregistrés
        """
        return list(self._entries.keys())

    def list_entries(self) -> List[DirectoryEntry]:
        """
        Retourne toutes les entrées de l'annuaire
        """
        return list(self._entries.values())

    # -- Affichage -----------------------------------------------------------

    def display(self) -> None:
        """
        Affiche un résumé de l'annuaire
        """
        print("\n" + "=" * 60)
        print("  ANNUAIRE DES CLÉS PUBLIQUES (Key Directory Server)")
        print("=" * 60)
        if not self._entries:
            print("  (annuaire vide)")
        else:
            for entry in self._entries.values():
                print(f"  {entry.summary()}")
        print("=" * 60 + "\n")
