#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

========================================================================
         VOLT v2 — PROTOCOLE DE CHIFFREMENT HYBRIDE POST-QUANTIQUE
                  Production-Grade Security Library — v2.1.0-hardened
========================================================================
Copyright 2026 Jonathan Evina (Sama) - RATISS Labs

CORRECTIONS DE SÉCURITÉ v2.1.0 :
  [FIX-01] Blocage du mode dégradé en production. Les primitives non-conformes
           (fallbacks SHA256/XOR) sont désormais bloquées par défaut. Un
           RuntimeError est levé si liboqs ou cryptography est absent en mode
           production. Le mode dégradé doit être explicitement activé via la
           variable d'environnement VOLT_ALLOW_DEGRADED=1 (tests uniquement).

  [FIX-02] Effacement cryptographique de la mémoire. Les secrets temporaires
           (shared_secret, clés dérivées) sont encapsulés dans SecretBuffer,
           un gestionnaire de contexte qui écrase les octets en mémoire avec
           des zéros via ctypes avant libération, minimisant la fenêtre
           d'exposition en RAM.

  [FIX-03] Limites strictes de taille sur la désérialisation. Chaque chunk
           est borné à sa taille maximale théorique (standard NIST) afin de
           prévenir les attaques par allocation mémoire excessive (DoS).

  [FIX-04] Validation explicite des types et tailles en entrée. Les fonctions
           encrypt, decrypt et generate_anchor_key rejettent maintenant
           explicitement les entrées malformées avant tout traitement.

  [FIX-05] Blocage des passphrases vides dans generate_anchor_key.

DOCUMENTATION & UTILISATION :
-----------------------------
Installation des dépendances (mode production obligatoire) :
  pip install cryptography liboqs-python --user --break-system-packages

Architecture :
  - AbstractKEM              : Interface pour l'encapsulation de clés
  - AbstractSignature        : Interface pour la signature post-quantique
  - AbstractSymmetricCipher  : Interface pour le chiffrement symétrique GCM
  - AbstractMAC              : Interface d'intégrité anti-temporelle
  - SecretBuffer             : Gestionnaire de mémoire sécurisée (zero-on-free)

Exemple d'utilisation :
  >>> from volt_v2_production import (
  ...     LiboqsKEM, LiboqsSignature, ProductionAESGCM, PythonHMAC,
  ...     VOLTProtocolEngine, generate_anchor_key
  ... )
  >>> engine = VOLTProtocolEngine(LiboqsKEM(), LiboqsSignature(),
  ...                              ProductionAESGCM(), PythonHMAC())
  >>> recipient_kem, recipient_sign = engine.generate_system_keys()
"""

from __future__ import annotations

import os
import sys
import site
import hmac
import ctypes
import struct
import hashlib
import importlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple

# ═══════════════════════════════════════════════════════════════════════
# CONTRÔLE DU MODE D'EXÉCUTION
# ═══════════════════════════════════════════════════════════════════════
# En mode production (défaut), tout fallback non-conforme est bloqué.
# Définir VOLT_ALLOW_DEGRADED=1 uniquement dans des environnements de test
# contrôlés. Ce flag ne doit JAMAIS être activé en production réelle.
_PRODUCTION_MODE: bool = os.environ.get('VOLT_ALLOW_DEGRADED', '0').strip() != '1'

# Limites de taille maximale des chunks pour la désérialisation (anti-DoS)
_MAX_PLAINTEXT_SIZE:  int = 64 * 1024 * 1024   # 64 Mo
_MAX_KEM_CT_SIZE:     int = 2048                 # Kyber768 CT nominal : 1088 B
_MAX_NONCE_SIZE:      int = 32                   # AES-GCM nonce : 12 B
_MAX_AES_CT_SIZE:     int = _MAX_PLAINTEXT_SIZE  # taille plaintext au plus
_MAX_AES_TAG_SIZE:    int = 32                   # AES-GCM tag : 16 B
_MAX_SIGNATURE_SIZE:  int = 8192                 # Dilithium3 sig : ~3293 B
_MAX_SENDER_PK_SIZE:  int = 2048                 # Kyber768 PK : 1184 B

# ─────────────────────────────────────────────────────────────────────
# Résolution des chemins Python (priorité aux wheels utilisateur)
# ─────────────────────────────────────────────────────────────────────
user_site = site.getusersitepackages()
if user_site not in sys.path:
    sys.path.append(user_site)
for _p in ["/root/.local/lib/python3.10/site-packages",
           "/usr/local/lib/python3.10/dist-packages"]:
    if _p not in sys.path:
        sys.path.append(_p)
importlib.invalidate_caches()

# ─────────────────────────────────────────────────────────────────────
# Imports conditionnels des primitives cryptographiques
# ─────────────────────────────────────────────────────────────────────
try:
    import oqs
    from oqs import KeyEncapsulation, Signature as OQSSignature
    _LIBOQS_AVAILABLE = True
except ImportError:
    oqs = None
    KeyEncapsulation = None
    OQSSignature = None
    _LIBOQS_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AESGCM_AVAILABLE = True
except ImportError:
    AESGCM = None
    _AESGCM_AVAILABLE = False

# Vérification de disponibilité en mode production
if _PRODUCTION_MODE:
    if not _LIBOQS_AVAILABLE:
        raise RuntimeError(
            "[VOLT-FATAL] liboqs-python est absent. Les primitives post-quantiques "
            "(Kyber768, Dilithium3) ne peuvent pas fonctionner. "
            "Installez : pip install liboqs-python\n"
            "Pour activer le mode dégradé (TESTS UNIQUEMENT) : "
            "export VOLT_ALLOW_DEGRADED=1"
        )
    if not _AESGCM_AVAILABLE:
        raise RuntimeError(
            "[VOLT-FATAL] cryptography est absent. AES-256-GCM ne peut pas fonctionner. "
            "Installez : pip install cryptography\n"
            "Pour activer le mode dégradé (TESTS UNIQUEMENT) : "
            "export VOLT_ALLOW_DEGRADED=1"
        )


# ═══════════════════════════════════════════════════════════════════════
# SECTION 0 — GESTION SÉCURISÉE DE LA MÉMOIRE
# ═══════════════════════════════════════════════════════════════════════

class SecretBuffer:
    """
    Gestionnaire de contexte pour les matériaux secrets en mémoire volatile.

    Encapsule un secret (bytes ou bytearray) dans un bytearray mutable
    et écrase les octets avec des zéros via ctypes.memset() dès la sortie
    du contexte, indépendamment des exceptions. Réduit la fenêtre
    d'exposition des secrets en RAM au strict minimum opérationnel.

    Usage :
        with SecretBuffer(shared_secret_bytes) as secret:
            result = cipher.encrypt(plaintext, bytes(secret))
        # secret est maintenant zéro en mémoire
    """

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecretBuffer n'accepte que bytes ou bytearray.")
        self._buf: bytearray = bytearray(data)
        self._length: int = len(self._buf)

    def __enter__(self) -> bytearray:
        return self._buf

    def __exit__(self, *_) -> None:
        self._zero()

    def _zero(self) -> None:
        """Écrase la mémoire avec des zéros via ctypes.memset (hors GC Python)."""
        if self._length > 0:
            try:
                addr = ctypes.addressof(
                    (ctypes.c_char * self._length).from_buffer(self._buf)
                )
                ctypes.memset(addr, 0, self._length)
            except Exception:
                # Dernier recours si ctypes échoue (environnement restreint)
                for i in range(self._length):
                    self._buf[i] = 0

    def __del__(self) -> None:
        self._zero()


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — STRUCTURES ET PACKAGES DE DONNÉES DU PROTOCOLE VOLT V2
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class KeyPair:
    """
    Paire de clés de sécurité universelle (Publique/Privée).
    Contient les octets bruts indispensables aux primitives post-quantiques.
    """
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class EncapsulationResult:
    """
    Résultat d'une encapsulation KEM.
    Contient le ciphertext réseau et le secret partagé (shared_secret).
    """
    ciphertext: bytes
    shared_secret: bytes


@dataclass(frozen=True)
class CiphertextPackage:
    """
    Spécification d'empaquetage standardisé pour la persistance RATISS VOLT v2.

    Structure physique :
      kem_ciphertext    : Chiffrement de clé par Kyber768 (~1088 octets)
      aes_nonce         : Nonce authentifié AES-GCM (12 octets)
      aes_ciphertext    : Données chiffrées (longueur = longueur plaintext)
      aes_tag           : Tag de vérification symétrique (16 octets)
      signature         : Signature numérique de l'expéditeur Dilithium3 (~3293 octets)
      hmac_value        : Tag d'intégrité HMAC-SHA256 (32 octets fixes)
      sender_public_key : Clé KEM publique de l'expéditeur (1184 octets)
    """
    kem_ciphertext: bytes
    aes_nonce: bytes
    aes_ciphertext: bytes
    aes_tag: bytes
    signature: bytes
    hmac_value: bytes
    sender_public_key: bytes

    _MAGIC   = b'VOLT'
    _VERSION = struct.pack('>HH', 0x0200, 0x0000)

    def serialize(self) -> bytes:
        """
        Sérialise le package en flux d'octets binaire normalisé Strict-Frame.
        Chaque chunk variable est précédé de sa longueur (>I, 4 octets gros-boutiste).
        Le HMAC (32 octets) est écrit sans préfixe longueur — taille fixe connue.
        """
        def pack_chunk(data: bytes) -> bytes:
            return struct.pack('>I', len(data)) + data

        header = self._MAGIC + self._VERSION
        body = (
            pack_chunk(self.kem_ciphertext) +
            pack_chunk(self.aes_nonce)      +
            pack_chunk(self.aes_ciphertext) +
            pack_chunk(self.aes_tag)        +
            pack_chunk(self.signature)      +
            self.hmac_value                 +   # 32 octets fixes — pas de préfixe
            pack_chunk(self.sender_public_key)
        )
        return header + body

    @classmethod
    def deserialize(cls, data: bytes) -> 'CiphertextPackage':
        """
        Désérialise un flux binaire en CiphertextPackage.
        Applique des contrôles stricts : Magic, Version, bornes de chaque chunk,
        et limites de taille maximale par segment (anti-DoS).
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("deserialize attend un objet bytes ou bytearray.")
        if len(data) < 8:
            raise ValueError("Dimensions binaires insuffisantes pour un package VOLT v2.")

        if data[:4] != cls._MAGIC:
            raise ValueError(
                f"En-tête Magic invalide : attendu {cls._MAGIC!r}, reçu {data[:4]!r}"
            )

        version = struct.unpack('>HH', data[4:8])
        if version[0] != 0x0200:
            raise ValueError(
                f"Version de chiffrement obsolète ou non reconnue : {version[0]:#06x}"
            )

        offset = 8

        def read_chunk(max_size: int, field_name: str) -> bytes:
            nonlocal offset
            if offset + 4 > len(data):
                raise ValueError(
                    f"Payload incomplet lors de la lecture du chunk '{field_name}'."
                )
            length = struct.unpack('>I', data[offset:offset + 4])[0]
            offset += 4
            if length > max_size:
                raise ValueError(
                    f"Chunk '{field_name}' trop grand : {length} octets > "
                    f"maximum autorisé {max_size} octets. Paquet rejeté (anti-DoS)."
                )
            if offset + length > len(data):
                raise ValueError(
                    f"Taille de chunk '{field_name}' corrompue : attendu {length} octets, "
                    f"disponible {len(data) - offset}."
                )
            chunk_data = data[offset:offset + length]
            offset += length
            return chunk_data

        try:
            kem_ct        = read_chunk(_MAX_KEM_CT_SIZE,    'kem_ciphertext')
            aes_nonce     = read_chunk(_MAX_NONCE_SIZE,     'aes_nonce')
            aes_ct        = read_chunk(_MAX_AES_CT_SIZE,    'aes_ciphertext')
            aes_tag_val   = read_chunk(_MAX_AES_TAG_SIZE,   'aes_tag')
            signature_val = read_chunk(_MAX_SIGNATURE_SIZE, 'signature')

            if offset + 32 > len(data):
                raise ValueError(
                    "Valeur de contrôle HMAC-SHA256 manquante ou tronquée."
                )
            hmac_val = data[offset:offset + 32]
            offset  += 32

            sender_pk = read_chunk(_MAX_SENDER_PK_SIZE, 'sender_public_key')

        except struct.error as e:
            raise ValueError(f"Échec d'analyse de structure binaire : {e}") from e

        return cls(
            kem_ciphertext=bytes(kem_ct),
            aes_nonce=bytes(aes_nonce),
            aes_ciphertext=bytes(aes_ct),
            aes_tag=bytes(aes_tag_val),
            signature=bytes(signature_val),
            hmac_value=bytes(hmac_val),
            sender_public_key=bytes(sender_pk),
        )


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — INTERFACES ABSTRAITES (CONTRATS ABC)
# ═══════════════════════════════════════════════════════════════════════

class AbstractKEM(ABC):
    """Abstraction du mécanisme d'encapsulation de clé (KEM) post-quantique."""

    @abstractmethod
    def keygen(self) -> KeyPair:
        """Génère une paire de clés publique/privée KEM."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """Génère un secret partagé et un ciphertext destiné au récepteur."""

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Dérive le secret partagé depuis le ciphertext et la clé privée."""


class AbstractSignature(ABC):
    """Abstraction du schéma de signature numérique post-quantique."""

    @abstractmethod
    def keygen(self) -> KeyPair:
        """Génère une paire de clés publique/privée de signature."""

    @abstractmethod
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Signe un message binaire avec la clé privée."""

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Vérifie l'authenticité d'une signature sur un message."""


class AbstractSymmetricCipher(ABC):
    """Abstraction du chiffrement symétrique AEAD."""

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes,
                associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        """Chiffre et retourne (nonce, ciphertext, tag)."""

    @abstractmethod
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes,
                key: bytes, associated_data: bytes = b'') -> bytes:
        """Déchiffre le ciphertext authentifié et retourne le plaintext."""


class AbstractMAC(ABC):
    """Abstraction du calculateur de code d'authentification de message."""

    @abstractmethod
    def compute(self, message: bytes, key: bytes) -> bytes:
        """Calcule un tag HMAC cryptographiquement sécurisé."""

    @abstractmethod
    def verify(self, message: bytes, mac: bytes, key: bytes) -> bool:
        """Vérifie un tag en temps constant (protection anti-timing)."""


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — IMPLÉMENTATIONS DE PRODUCTION
# ═══════════════════════════════════════════════════════════════════════

def _assert_production_primitive(lib_name: str, available: bool) -> None:
    """
    Lève RuntimeError si une primitive est absente en mode production.
    En mode dégradé explicitement autorisé, émet un avertissement visible.
    """
    if not available:
        if _PRODUCTION_MODE:
            raise RuntimeError(
                f"[VOLT-FATAL] {lib_name} est requis en mode production mais est absent. "
                "Installez les dépendances ou exportez VOLT_ALLOW_DEGRADED=1 pour les tests."
            )
        import warnings
        warnings.warn(
            f"[VOLT-DEGRADED] {lib_name} absent — utilisation d'un fallback NON SÉCURISÉ. "
            "CE MODE EST INTERDIT EN PRODUCTION.",
            stacklevel=3,
            category=SecurityWarning,
        )


class LiboqsKEM(AbstractKEM):
    """
    Implémentation Kyber768 (ML-KEM, FIPS 203) via liboqs.
    En mode production, liboqs est obligatoire — tout fallback est bloqué.
    """
    ALG_NAME = 'Kyber768'

    def keygen(self) -> KeyPair:
        _assert_production_primitive('liboqs (Kyber768)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            return KeyPair(os.urandom(1184), os.urandom(2400))
        with KeyEncapsulation(self.ALG_NAME) as kem:
            public_key  = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return KeyPair(public_key, private_key)

    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        if not isinstance(public_key, bytes):
            raise TypeError("encapsulate attend une clé publique de type bytes.")
        _assert_production_primitive('liboqs (Kyber768)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            ct = os.urandom(1088)
            ss = hashlib.sha256(public_key).digest()
            return EncapsulationResult(ct, ss)
        with KeyEncapsulation(self.ALG_NAME) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return EncapsulationResult(ciphertext, shared_secret)

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        if not isinstance(ciphertext, bytes) or not isinstance(private_key, bytes):
            raise TypeError("decapsulate attend des arguments de type bytes.")
        _assert_production_primitive('liboqs (Kyber768)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            return hashlib.sha256(private_key).digest()
        with KeyEncapsulation(self.ALG_NAME, private_key) as kem:
            return kem.decap_secret(ciphertext)


class LiboqsSignature(AbstractSignature):
    """
    Implémentation Dilithium3 (ML-DSA, FIPS 204) via liboqs.
    En mode production, liboqs est obligatoire — tout fallback est bloqué.
    """
    ALG_NAME = 'Dilithium3'

    def keygen(self) -> KeyPair:
        _assert_production_primitive('liboqs (Dilithium3)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            return KeyPair(os.urandom(1952), os.urandom(4016))
        with OQSSignature(self.ALG_NAME) as sig:
            public_key  = sig.generate_keypair()
            private_key = sig.export_secret_key()
        return KeyPair(public_key, private_key)

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        if not isinstance(message, bytes) or not isinstance(private_key, bytes):
            raise TypeError("sign attend des arguments de type bytes.")
        _assert_production_primitive('liboqs (Dilithium3)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            return hmac.new(private_key, message, hashlib.sha256).digest()
        with OQSSignature(self.ALG_NAME, private_key) as sig:
            return sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if not all(isinstance(x, bytes) for x in (message, signature, public_key)):
            raise TypeError("verify attend des arguments de type bytes.")
        _assert_production_primitive('liboqs (Dilithium3)', _LIBOQS_AVAILABLE)
        if not _LIBOQS_AVAILABLE:
            expected = hmac.new(public_key, message, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)
        with OQSSignature(self.ALG_NAME) as sig:
            try:
                return sig.verify(message, signature, public_key)
            except Exception:
                return False


class ProductionAESGCM(AbstractSymmetricCipher):
    """
    Chiffrement AEAD AES-256-GCM via la bibliothèque cryptography (OpenSSL).
    En mode production, cryptography est obligatoire — tout fallback est bloqué.
    """
    _NONCE_LEN = 12
    _TAG_LEN   = 16

    def encrypt(self, plaintext: bytes, key: bytes,
                associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        if not isinstance(plaintext, bytes):
            raise TypeError("encrypt : plaintext doit être de type bytes.")
        if len(plaintext) > _MAX_PLAINTEXT_SIZE:
            raise ValueError(
                f"Plaintext trop grand : {len(plaintext)} octets > "
                f"maximum {_MAX_PLAINTEXT_SIZE} octets."
            )
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("encrypt : key doit être de type bytes ou bytearray.")

        key_derived = key if len(key) == 32 else hashlib.sha256(bytes(key)).digest()

        _assert_production_primitive('cryptography (AES-256-GCM)', _AESGCM_AVAILABLE)
        if not _AESGCM_AVAILABLE:
            nonce = os.urandom(self._NONCE_LEN)
            keystream = hashlib.sha256(key_derived + nonce).digest()
            while len(keystream) < len(plaintext):
                keystream += hashlib.sha256(keystream).digest()
            ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
            tag = hmac.new(
                key_derived,
                ciphertext + nonce + associated_data,
                hashlib.sha256
            ).digest()[:self._TAG_LEN]
            return nonce, ciphertext, tag

        aes_gcm         = AESGCM(key_derived)
        nonce           = os.urandom(self._NONCE_LEN)
        cipher_with_tag = aes_gcm.encrypt(nonce, plaintext, associated_data or None)
        ciphertext      = cipher_with_tag[:-self._TAG_LEN]
        tag             = cipher_with_tag[-self._TAG_LEN:]
        return nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes,
                key: bytes, associated_data: bytes = b'') -> bytes:
        if not all(isinstance(x, (bytes, bytearray)) for x in (nonce, ciphertext, tag, key)):
            raise TypeError("decrypt : tous les arguments doivent être bytes ou bytearray.")
        if len(nonce) != self._NONCE_LEN:
            raise ValueError(
                f"Taille de nonce AES-GCM invalide : {len(nonce)} au lieu de {self._NONCE_LEN}."
            )
        if len(tag) != self._TAG_LEN:
            raise ValueError(
                f"Taille de tag AES-GCM invalide : {len(tag)} au lieu de {self._TAG_LEN}."
            )

        key_derived = bytes(key) if len(key) == 32 else hashlib.sha256(bytes(key)).digest()

        _assert_production_primitive('cryptography (AES-256-GCM)', _AESGCM_AVAILABLE)
        if not _AESGCM_AVAILABLE:
            computed_tag = hmac.new(
                key_derived,
                bytes(ciphertext) + bytes(nonce) + associated_data,
                hashlib.sha256
            ).digest()[:self._TAG_LEN]
            if not hmac.compare_digest(computed_tag, bytes(tag)):
                raise ValueError("Intégrité AEAD corrompue lors du déchiffrement (mode dégradé).")
            keystream = hashlib.sha256(key_derived + bytes(nonce)).digest()
            while len(keystream) < len(ciphertext):
                keystream += hashlib.sha256(keystream).digest()
            return bytes(a ^ b for a, b in zip(ciphertext, keystream))

        aes_gcm = AESGCM(key_derived)
        return aes_gcm.decrypt(bytes(nonce), bytes(ciphertext) + bytes(tag), associated_data or None)


class PythonHMAC(AbstractMAC):
    """
    Calculateur HMAC-SHA256 avec protection totale contre les attaques temporelles.
    Utilise hmac.compare_digest pour toutes les comparaisons. Aucun fallback requis
    (hashlib et hmac font partie de la bibliothèque standard Python).
    """

    def compute(self, message: bytes, key: bytes) -> bytes:
        if not isinstance(message, bytes) or not isinstance(key, (bytes, bytearray)):
            raise TypeError("HMAC.compute : message (bytes) et key (bytes) requis.")
        key_derived = bytes(key) if len(key) == 32 else hashlib.sha256(bytes(key)).digest()
        return hmac.new(key_derived, message, hashlib.sha256).digest()

    def verify(self, message: bytes, mac: bytes, key: bytes) -> bool:
        expected = self.compute(message, key)
        return hmac.compare_digest(expected, mac)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — ANCHOR KEY SYSTEM (MASQUAGE ERGONOMIQUE DES CLÉS NIST)
# ═══════════════════════════════════════════════════════════════════════

def generate_anchor_key(passphrase: str, smgs_constants: dict) -> str:
    """
    Dérive de manière déterministe une clé d'ancrage condensée de 48 caractères
    hexadécimaux (24 octets) à partir d'une passphrase maître et des constantes
    physiques SMGS (delta_f, d_eff).

    Sécurité :
      - PBKDF2-HMAC-SHA256 avec 10 000 itérations
      - Sel construit déterministement depuis les constantes SMGS (précision 6 décimales)
      - Passphrase vide rejetée explicitement
      - Les constantes SMGS sont validées en type flottant avant usage

    Args:
        passphrase    : Secret maître de l'utilisateur (non vide).
        smgs_constants: Dictionnaire contenant 'delta_f' et 'd_eff'.

    Returns:
        Chaîne hexadécimale majuscule de 48 caractères.

    Raises:
        ValueError  : Si la passphrase est vide ou si les constantes sont invalides.
        TypeError   : Si les types d'entrée sont incorrects.
    """
    if not isinstance(passphrase, str):
        raise TypeError("generate_anchor_key : passphrase doit être une chaîne str.")
    if not passphrase.strip():
        raise ValueError(
            "generate_anchor_key : la passphrase ne peut pas être vide ou composée "
            "uniquement d'espaces. Une passphrase forte est obligatoire."
        )
    if not isinstance(smgs_constants, dict):
        raise TypeError("generate_anchor_key : smgs_constants doit être un dict.")

    try:
        delta_f = float(smgs_constants.get('delta_f', 4.669201))
        d_eff   = float(smgs_constants.get('d_eff',   1.584962))
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"generate_anchor_key : constantes SMGS invalides — {e}"
        ) from e

    salt_str = (
        f"RATISS:SMGS_CALIBRATION:"
        f"delta_f={delta_f:.6f}:"
        f"d_eff={d_eff:.6f}"
    )
    salt = salt_str.encode('utf-8')

    derived_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt,
        iterations=10000,
        dklen=24,
    )
    return derived_bytes.hex().upper()


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5 — MOTEUR PROTOCOLAIRE (ORCHESTRE / INJECTION DE DÉPENDANCES)
# ═══════════════════════════════════════════════════════════════════════

class VOLTProtocolEngine:
    """
    Moteur de sécurité VOLT v2 — séquence ordonnée Encrypt-then-Sign-then-MAC.

    Orchestre les quatre primitives via injection de dépendances explicite.
    Les secrets intermédiaires (shared_secret, mac_key) sont protégés par
    SecretBuffer et effacés en mémoire dès que leur usage est terminé.
    """
    _MAGIC   = b'VOLT'
    _VERSION = struct.pack('>HH', 0x0200, 0x0000)

    def __init__(
        self,
        kem:       AbstractKEM,
        signature: AbstractSignature,
        cipher:    AbstractSymmetricCipher,
        mac:       AbstractMAC,
    ) -> None:
        if not isinstance(kem, AbstractKEM):
            raise TypeError("VOLTProtocolEngine : kem doit implémenter AbstractKEM.")
        if not isinstance(signature, AbstractSignature):
            raise TypeError("VOLTProtocolEngine : signature doit implémenter AbstractSignature.")
        if not isinstance(cipher, AbstractSymmetricCipher):
            raise TypeError("VOLTProtocolEngine : cipher doit implémenter AbstractSymmetricCipher.")
        if not isinstance(mac, AbstractMAC):
            raise TypeError("VOLTProtocolEngine : mac doit implémenter AbstractMAC.")
        self.kem       = kem
        self.signature = signature
        self.cipher    = cipher
        self.mac       = mac

    def generate_system_keys(self) -> Tuple[KeyPair, KeyPair]:
        """
        Génère un trousseau Kyber768 et un trousseau Dilithium3.
        Retourne (kem_keypair, signature_keypair).
        """
        return self.kem.keygen(), self.signature.keygen()

    def _build_signed_body(
        self,
        kem_ct:  bytes,
        nonce:   bytes,
        aes_ct:  bytes,
        aes_tag: bytes,
    ) -> bytes:
        """
        Construit le bloc interne soumis à la signature Dilithium3.
        Structure : MAGIC(4) + VERSION(4) + kem_ct + nonce + aes_ct + aes_tag.
        """
        return self._MAGIC + self._VERSION + kem_ct + nonce + aes_ct + aes_tag

    def encrypt(
        self,
        plaintext:        bytes,
        recipient_kem_pk: bytes,
        sender_sign_sk:   bytes,
        sender_kem_pk:    bytes,
    ) -> CiphertextPackage:
        """
        Chiffrement hybride post-quantique — séquence Encrypt → Sign → MAC.

        1. Kyber768 encapsule un shared_secret depuis recipient_kem_pk.
        2. AES-256-GCM chiffre le plaintext avec le shared_secret.
        3. Dilithium3 signe le bloc (MAGIC+VERSION+kem_ct+nonce+ct+tag).
        4. HMAC-SHA256 couvre (bloc_signé + signature) avec mac_key = SHA256(shared_secret).
        5. Le shared_secret et mac_key sont effacés de la mémoire via SecretBuffer.

        Args:
            plaintext        : Données à chiffrer (bytes).
            recipient_kem_pk : Clé publique KEM Kyber768 du destinataire.
            sender_sign_sk   : Clé privée de signature Dilithium3 de l'expéditeur.
            sender_kem_pk    : Clé publique KEM de l'expéditeur (incluse dans le paquet).

        Returns:
            CiphertextPackage sérialisable.

        Raises:
            TypeError  : Si un argument n'est pas de type bytes.
            ValueError : Si le plaintext dépasse la taille maximale autorisée.
        """
        for name, val in [
            ('plaintext', plaintext),
            ('recipient_kem_pk', recipient_kem_pk),
            ('sender_sign_sk', sender_sign_sk),
            ('sender_kem_pk', sender_kem_pk),
        ]:
            if not isinstance(val, bytes):
                raise TypeError(f"encrypt : '{name}' doit être de type bytes.")
        if len(plaintext) > _MAX_PLAINTEXT_SIZE:
            raise ValueError(
                f"Plaintext trop grand : {len(plaintext)} octets > maximum {_MAX_PLAINTEXT_SIZE}."
            )

        kem_res = self.kem.encapsulate(recipient_kem_pk)

        with SecretBuffer(kem_res.shared_secret) as raw_secret:
            secret_bytes = bytes(raw_secret)

            nonce, aes_ct, aes_tag = self.cipher.encrypt(plaintext, secret_bytes)
            payload_body            = self._build_signed_body(
                kem_res.ciphertext, nonce, aes_ct, aes_tag
            )
            signature_value = self.signature.sign(payload_body, sender_sign_sk)

            with SecretBuffer(hashlib.sha256(secret_bytes).digest()) as raw_mac_key:
                mac_key       = bytes(raw_mac_key)
                full_payload  = payload_body + signature_value
                hmac_value    = self.mac.compute(full_payload, mac_key)

        return CiphertextPackage(
            kem_ciphertext=kem_res.ciphertext,
            aes_nonce=nonce,
            aes_ciphertext=aes_ct,
            aes_tag=aes_tag,
            signature=signature_value,
            hmac_value=hmac_value,
            sender_public_key=sender_kem_pk,
        )

    def decrypt(
        self,
        package:         CiphertextPackage,
        recipient_kem_sk: bytes,
        sender_sign_pk:  bytes,
    ) -> bytes:
        """
        Déchiffrement authentifié — séquence Fail-Fast : HMAC → Signature → AES.

        1. Kyber768 décapsule le shared_secret.
        2. HMAC-SHA256 est vérifié EN PREMIER. Tout échec → ValueError immédiat.
           Aucun déchiffrement partiel n'est tenté avant validation HMAC complète.
        3. Dilithium3 est vérifié. Tout échec → ValueError immédiat.
        4. AES-256-GCM déchiffre et retourne le plaintext.
        5. Le shared_secret et mac_key sont effacés de la mémoire via SecretBuffer.

        Args:
            package          : CiphertextPackage désérialisé.
            recipient_kem_sk : Clé privée KEM Kyber768 du destinataire.
            sender_sign_pk   : Clé publique de signature Dilithium3 de l'expéditeur.

        Returns:
            Plaintext original (bytes).

        Raises:
            TypeError  : Si un argument est de type incorrect.
            ValueError : En cas de rupture HMAC ou de signature invalide.
        """
        if not isinstance(package, CiphertextPackage):
            raise TypeError("decrypt : package doit être un CiphertextPackage.")
        for name, val in [
            ('recipient_kem_sk', recipient_kem_sk),
            ('sender_sign_pk', sender_sign_pk),
        ]:
            if not isinstance(val, bytes):
                raise TypeError(f"decrypt : '{name}' doit être de type bytes.")

        raw_secret = self.kem.decapsulate(package.kem_ciphertext, recipient_kem_sk)

        with SecretBuffer(raw_secret) as buf_secret:
            secret_bytes = bytes(buf_secret)

            payload_body = self._build_signed_body(
                package.kem_ciphertext,
                package.aes_nonce,
                package.aes_ciphertext,
                package.aes_tag,
            )
            full_payload = payload_body + package.signature

            with SecretBuffer(hashlib.sha256(secret_bytes).digest()) as buf_mac_key:
                mac_key = bytes(buf_mac_key)

                # ── VÉRIFICATION HMAC EN PREMIER (Fail-Fast) ──────────────
                if not self.mac.verify(full_payload, package.hmac_value, mac_key):
                    raise ValueError(
                        "RUPTURE DE SÉCURITÉ CRITIQUE : "
                        "Signature de contrôle HMAC invalide. Paquet altéré."
                    )

            # ── VÉRIFICATION SIGNATURE DILITHIUM3 ─────────────────────────
            if not self.signature.verify(payload_body, package.signature, sender_sign_pk):
                raise ValueError(
                    "RUPTURE DE SÉCURITÉ CRITIQUE : "
                    "Signature post-quantique Dilithium3 invalide ou usurpée."
                )

            # ── DÉCHIFFREMENT AES-256-GCM (après double validation) ───────
            plaintext = self.cipher.decrypt(
                package.aes_nonce,
                package.aes_ciphertext,
                package.aes_tag,
                secret_bytes,
            )

        return plaintext


# ═══════════════════════════════════════════════════════════════════════
# SECTION 6 — SUITE DE CERTIFICATION DE PRODUCTION INTÉGRÉE
# ═══════════════════════════════════════════════════════════════════════

def run_production_tests() -> bool:
    """
    Suite de certification de l'ingénierie VOLT v2.
    Valide l'intégrité de l'environnement d'exécution avant tout déploiement.
    """
    print("[INIT] Lancement de la suite de certification VOLT v2 (v2.1.0-hardened)...")

    # Étape 1 — Injection des primitives
    try:
        kem    = LiboqsKEM()
        sig    = LiboqsSignature()
        cipher = ProductionAESGCM()
        mac    = PythonHMAC()
        engine = VOLTProtocolEngine(kem, sig, cipher, mac)
        print("  [PASS] Étape 1 : Injection des primitives et initialisation OK.")
    except Exception as e:
        print(f"  [FAIL] Étape 1 : Échec lors du chargement ou de l'injection : {e}")
        return False

    # Étape 2 — Génération de clés NIST
    try:
        recipient_kem, sender_sign = engine.generate_system_keys()
        sender_kem, _              = engine.generate_system_keys()
        assert len(recipient_kem.public_key) > 0,  "Public Key KEM vide"
        assert len(recipient_kem.private_key) > 0, "Private Key KEM vide"
        assert len(sender_sign.public_key) > 0,    "Public Key Sign vide"
        assert len(sender_sign.private_key) > 0,   "Private Key Sign vide"
        print("  [PASS] Étape 2 : Génération de clés NIST conforme.")
    except Exception as e:
        print(f"  [FAIL] Étape 2 : Échec génération de clés PQC : {e}")
        return False

    # Étape 3 — Anchor Key : déterminisme, sensibilité au sel, rejet passphrase vide
    try:
        c1   = {"delta_f": 4.669201, "d_eff": 1.584962}
        c2   = {"delta_f": 4.669201, "d_eff": 1.584962}
        cdif = {"delta_f": 4.669201, "d_eff": 1.580000}
        pwd  = "RATISS_SAMA_SECRET_PHRASE"

        a1 = generate_anchor_key(pwd, c1)
        a2 = generate_anchor_key(pwd, c2)
        ad = generate_anchor_key(pwd, cdif)

        assert len(a1) == 48,    f"Longueur invalide : {len(a1)}"
        assert a1 == a2,         "Déterminisme violé"
        assert a1 != ad,         "Indépendance du sel physique violée"

        # Vérification du rejet de passphrase vide
        try:
            generate_anchor_key("", c1)
            print("  [FAIL] Étape 3 : Passphrase vide acceptée (faille).")
            return False
        except ValueError:
            pass

        print(f"  [PASS] Étape 3 : Anchor Key validée. Empreinte : {a1}")
    except Exception as e:
        print(f"  [FAIL] Étape 3 : Échec du protocole d'Anchor Key : {e}")
        return False

    # Étape 4 — Cycle cryptographique complet E2E
    try:
        message_original = b"CONFIDENTIEL SAMA : Sequence d'alignement holomorphique valide."
        package = engine.encrypt(
            plaintext=message_original,
            recipient_kem_pk=recipient_kem.public_key,
            sender_sign_sk=sender_sign.private_key,
            sender_kem_pk=sender_kem.public_key,
        )
        serialized = package.serialize()
        assert serialized.startswith(b'VOLT'), "Magic header binaire absent"
        recovered = CiphertextPackage.deserialize(serialized)
        decrypted = engine.decrypt(
            package=recovered,
            recipient_kem_sk=recipient_kem.private_key,
            sender_sign_pk=sender_sign.public_key,
        )
        assert decrypted == message_original, "Texte déchiffré invalide"
        print("  [PASS] Étape 4 : Chiffrement hybride, sérialisation et déchiffrement validés.")
    except Exception as e:
        print(f"  [FAIL] Étape 4 : Échec du cycle cryptographique : {e}")
        return False

    # Étape 5 — Injection de fautes (rejet HMAC)
    try:
        serialized   = package.serialize()
        corrupt_idx  = len(serialized) - 40
        corrupted    = bytearray(serialized)
        corrupted[corrupt_idx] ^= 0xFF
        bad_package  = CiphertextPackage.deserialize(bytes(corrupted))
        try:
            engine.decrypt(
                package=bad_package,
                recipient_kem_sk=recipient_kem.private_key,
                sender_sign_pk=sender_sign.public_key,
            )
            print("  [FAIL] Étape 5 : L'enveloppe corrompue a été acceptée (faille).")
            return False
        except ValueError:
            print("  [PASS] Étape 5 : Altération détectée. Pare-feu HMAC/Dilithium actif.")
    except Exception as e:
        print(f"  [FAIL] Étape 5 : Erreur durant l'injection de fautes : {e}")
        return False

    # Étape 6 — Rejet des paquets DoS (chunk surdimensionné)
    try:
        fake_data = b'VOLT' + struct.pack('>HH', 0x0200, 0x0000)
        fake_data += struct.pack('>I', _MAX_KEM_CT_SIZE + 1) + b'\x00' * (_MAX_KEM_CT_SIZE + 1)
        try:
            CiphertextPackage.deserialize(fake_data)
            print("  [FAIL] Étape 6 : Chunk surdimensionné accepté (faille DoS).")
            return False
        except ValueError:
            print("  [PASS] Étape 6 : Chunk DoS rejeté par les limites de taille.")
    except Exception as e:
        print(f"  [FAIL] Étape 6 : Erreur durant le test anti-DoS : {e}")
        return False

    print("[SUCCESS] Suite de certification VOLT v2 validée à 100% (6/6 tests) !")
    return True


if __name__ == "__main__":
    run_production_tests()
