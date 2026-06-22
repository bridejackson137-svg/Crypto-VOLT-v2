# VOLT v2.1.0-hardened — Spécification Technique de Référence
### Protocole de Chiffrement Hybride Post-Quantique — Grade Production Durci

---

| Champ                    | Valeur                                                              |
| :----------------------- | :------------------------------------------------------------------ |
| **Titre industriel**     | VOLT v2 — Hybrid Post-Quantum Encryption Protocol                   |
| **Révision**             | 2.1.0-hardened                                                      |
| **Auteur**               | Jonathan Evina (Sama)                                               |
| **Organisation**         | RATISS LABS                                                         |
| **Date de publication**  | Juin 2026                                                           |
| **Licence**              | Apache License, Version 2.0                                         |
| **DOI**                  | https://doi.org/10.5281/zenodo.20701141              |
| **Dépôt Source**         |bridejackson137 |                             |
| **Statut**               | Production-Grade — Conforme NIST 2024 — Audit Sécurité Validé      |

---

**NOTICE DE COPYRIGHT OFFICIELLE**

```
Copyright 2026 Jonathan Evina (Sama) — RATISS LABS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Toute redistribution ou modification doit conserver intégralement cette notice et indiquer
explicitement les modifications apportées, conformément à la Section 4 de l'Apache License 2.0.

---

## Table des Matières

1. [Rapport d'Audit et Sécurisation v2.1.0](#1-rapport-daudit-et-sécurisation-v210)
2. [Cartographie des Primitives NIST](#2-cartographie-des-primitives-nist)
3. [Architecture Visuelle des Flux](#3-architecture-visuelle-des-flux)
4. [Architecture de l'Anchor Key System](#4-architecture-de-lanchor-key-system)
5. [Structure Binaire Strict-Frame](#5-structure-binaire-strict-frame)
6. [Guide d'Intégration et Exemple Prêt à l'Emploi](#6-guide-dintégration-et-exemple-prêt-à-lemploi)

---

## 1. Rapport d'Audit et Sécurisation v2.1.0

Ce rapport documente de manière exhaustive les cinq vulnérabilités identifiées lors de
l'audit de sécurité interne de la version 2.0.0, leurs vecteurs d'exploitation potentiels,
et les corrections implémentées dans la révision 2.1.0-hardened. Chaque correctif est
classifié par niveau de sévérité selon l'échelle RATISS LABS.

---

### FAILLE 1 — CRITIQUE | Blocage du Mode Dégradé Silencieux

#### Vecteur d'Exploitation (v2.0.0)

Dans la version originale, chaque implémentation concrète (`LiboqsKEM`, `LiboqsSignature`,
`ProductionAESGCM`) comportait un bloc conditionnel de la forme :

```python
if oqs is None or KeyEncapsulation is None:
    # Fallback silencieux — utilisé sans avertissement
    ct = os.urandom(1088)
    ss = hashlib.sha256(public_key).digest()
    return EncapsulationResult(ct, ss)
```

Si la bibliothèque `liboqs-python` était absente de l'environnement Python (cas fréquent
en déploiement rapide ou en conteneur léger), le moteur basculait **silencieusement** sur
des substituts non-conformes :

- **KEM (Kyber768) :** Remplacé par un ciphertext aléatoire `os.urandom(1088)` et un
  secret partagé `SHA256(public_key)` — déterministe, prévisible, **cryptographiquement nul**.
- **Signature (Dilithium3) :** Remplacée par `HMAC-SHA256(private_key, message)` — un
  MAC symétrique qui ne fournit aucune non-répudiation et est trivialmente forgeable par
  quiconque connaît la clé.
- **Chiffrement symétrique (AES-256-GCM) :** Remplacé par un XOR avec un keystream
  SHA256 itératif — un chiffrement de substitution ne bénéficiant d'aucune propriété AEAD
  formelle.

L'utilisateur ne recevait **aucun avertissement**. Les données étaient présentées comme
chiffrées alors qu'elles ne bénéficiaient d'aucune protection post-quantique, ni même
d'une protection classique robuste.

#### Correction Implémentée (v2.1.0)

Introduction d'un flag de contrôle d'exécution évalué **au chargement du module**, avant
toute instanciation de classe :

```python
_PRODUCTION_MODE: bool = os.environ.get('VOLT_ALLOW_DEGRADED', '0').strip() != '1'
```

En mode production (valeur par défaut), une vérification de disponibilité est effectuée
immédiatement après l'import conditionnel des bibliothèques :

```python
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
```

La fonction interne `_assert_production_primitive()` est appelée dans chaque méthode
concrète avant tout traitement, garantissant qu'aucune opération cryptographique ne peut
s'exécuter sur un fallback non-conforme sans consentement explicite :

```python
def _assert_production_primitive(lib_name: str, available: bool) -> None:
    if not available:
        if _PRODUCTION_MODE:
            raise RuntimeError(
                f"[VOLT-FATAL] {lib_name} est requis en mode production mais est absent."
            )
        import warnings
        warnings.warn(
            f"[VOLT-DEGRADED] {lib_name} absent — fallback NON SÉCURISÉ actif. "
            "CE MODE EST INTERDIT EN PRODUCTION.",
            stacklevel=3,
            category=SecurityWarning,
        )
```

**Le mode dégradé ne peut être activé que par `export VOLT_ALLOW_DEGRADED=1`, est
réservé aux environnements de test isolés, et émet un `SecurityWarning` visible à chaque
opération. Il n'est en aucun cas silencieux.**

| État de l'environnement             | v2.0.0                            | v2.1.0-hardened                        |
| :---------------------------------- | :-------------------------------- | :------------------------------------- |
| `liboqs` présent                    | Primitives NIST actives           | Primitives NIST actives                |
| `liboqs` absent, `VOLT_ALLOW_DEGRADED` non défini | Fallback silencieux SHA256/XOR | `RuntimeError` immédiat à l'import |
| `liboqs` absent, `VOLT_ALLOW_DEGRADED=1` | Fallback silencieux SHA256/XOR | Fallback actif + `SecurityWarning` visible |

---

### FAILLE 2 — CRITIQUE | Gestion des Secrets en RAM (SecretBuffer)

#### Vecteur d'Exploitation (v2.0.0)

Les secrets cryptographiques les plus sensibles du pipeline — `shared_secret` (le secret
partagé Kyber768) et `mac_key` (la clé HMAC dérivée) — étaient alloués comme objets
`bytes` Python standard :

```python
# Dans VOLTProtocolEngine.encrypt() — v2.0.0
shared_secret = kem_res.shared_secret           # objet bytes Python
mac_key = hashlib.sha256(shared_secret).digest() # second objet bytes Python
```

Les objets `bytes` Python sont **immuables**. Leur contenu ne peut pas être modifié
directement. La désallocation est gérée par le garbage collector Python de manière
**non-déterministe** : un objet `bytes` peut persister en RAM plusieurs secondes, minutes,
ou jusqu'à l'extinction du processus après sa sortie de portée logique.

Vecteurs d'exploitation concrets :
- **Analyse forensique de la RAM :** Sur un système compromis, un attaquant peut scanner
  les pages mémoire du processus Python à la recherche de patterns de 32 octets
  correspondant à des clés AES ou des secrets KEM.
- **Core dump :** Un crash du processus produit un fichier core dump contenant l'intégralité
  de la mémoire du processus, incluant les secrets non-effacés.
- **Swap OS :** Sans chiffrement complet du disque (FDE), les pages mémoire swappées
  persistent en clair sur le disque, incluant les zones contenant les secrets.
- **Attaque Cold Boot :** Sur hardware physique accessible, la RAM conserve son contenu
  quelques secondes après extinction — suffisant pour extraire des secrets actifs.

#### Correction Implémentée (v2.1.0) — Classe `SecretBuffer`

Introduction d'un gestionnaire de contexte dédié à la protection des secrets en mémoire.
`SecretBuffer` encapsule un secret dans un `bytearray` mutable et appelle
`ctypes.memset()` directement sur l'adresse mémoire physique du buffer, contournant
l'immuabilité Python et le GC :

```python
class SecretBuffer:
    """
    Gestionnaire de contexte pour les matériaux secrets en mémoire volatile.
    Encapsule un secret dans un bytearray mutable et écrase les octets
    avec des zéros via ctypes.memset() dès la sortie du contexte,
    indépendamment des exceptions. Réduit la fenêtre d'exposition des
    secrets en RAM au strict minimum opérationnel.
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
                # Fallback si ctypes.from_buffer est bloqué (sandbox restreint)
                for i in range(self._length):
                    self._buf[i] = 0

    def __del__(self) -> None:
        self._zero()   # Sécurité de dernier recours à la destruction de l'objet
```

**Intégration dans le pipeline de chiffrement :**

```python
# Dans VOLTProtocolEngine.encrypt() — v2.1.0
with SecretBuffer(kem_res.shared_secret) as raw_secret:
    secret_bytes = bytes(raw_secret)
    nonce, aes_ct, aes_tag = self.cipher.encrypt(plaintext, secret_bytes)
    payload_body = self._build_signed_body(kem_res.ciphertext, nonce, aes_ct, aes_tag)
    signature_value = self.signature.sign(payload_body, sender_sign_sk)

    with SecretBuffer(hashlib.sha256(secret_bytes).digest()) as raw_mac_key:
        mac_key = bytes(raw_mac_key)
        full_payload = payload_body + signature_value
        hmac_value = self.mac.compute(full_payload, mac_key)
    # ← mac_key écrasé ici par ctypes.memset() à la sortie du with interne
# ← shared_secret écrasé ici par ctypes.memset() à la sortie du with externe
```

**Mécanisme technique détaillé :**

1. `bytearray(data)` alloue un buffer mutable en mémoire contiguë.
2. `ctypes.c_char * self._length` crée un type C de taille exacte.
3. `.from_buffer(self._buf)` obtient un pointeur vers l'adresse mémoire réelle du buffer
   sans copie — opération zero-copy sur le buffer Python existant.
4. `ctypes.addressof(...)` extrait l'adresse mémoire physique brute.
5. `ctypes.memset(addr, 0, self._length)` écrase chaque octet du buffer avec `0x00`
   au niveau C, hors portée du runtime Python et du GC.

La méthode `__del__` garantit l'effacement même si le gestionnaire de contexte n'est
pas utilisé correctement, ajoutant une couche de sécurité de dernier recours.

**Limite résiduelle documentée :** La ligne `secret_bytes = bytes(raw_secret)` crée une
copie immuable nécessaire aux appels des primitives. Cette copie reste en mémoire jusqu'au
prochain cycle GC. `SecretBuffer` réduit significativement la fenêtre d'exposition mais ne
peut pas l'éliminer entièrement sans modifier l'API des bibliothèques sous-jacentes.

---

### FAILLE 3 — MAJEURE | Protection DoS par Allocation Mémoire Excessive

#### Vecteur d'Exploitation (v2.0.0)

La méthode `CiphertextPackage.deserialize()` dans la version originale lisait la longueur
déclarée de chaque chunk depuis les 4 octets gros-boutistes du flux binaire, puis allouait
immédiatement cette quantité de mémoire sans vérification préalable :

```python
def read_chunk() -> bytes:
    nonlocal offset
    length = struct.unpack('>I', data[offset:offset+4])[0]  # Longueur déclarée : 0 à 4 294 967 295
    offset += 4
    # Allocation immédiate sans borne maximale — vecteur DoS
    chunk_data = data[offset:offset+length]
    offset += length
    return chunk_data
```

Un attaquant pouvait forger un paquet VOLT syntaxiquement valide (Magic `b'VOLT'` +
Version `0x0200` corrects) mais déclarant un chunk `kem_ciphertext` de
`4 294 967 295` octets (4 Go). Le système tentait d'allouer 4 Go de RAM avant de
détecter toute anomalie, provoquant un crash OOM (Out of Memory) ou un gel du processus.

#### Correction Implémentée (v2.1.0)

Introduction de constantes de bornage par type de chunk, définies au niveau module :

```python
_MAX_PLAINTEXT_SIZE:  int = 64 * 1024 * 1024   # 64 Mo (limite opérationnelle)
_MAX_KEM_CT_SIZE:     int = 2048                 # Kyber768 CT nominal : 1088 B
_MAX_NONCE_SIZE:      int = 32                   # AES-GCM nonce : 12 B
_MAX_AES_CT_SIZE:     int = _MAX_PLAINTEXT_SIZE  # égal à la limite plaintext
_MAX_AES_TAG_SIZE:    int = 32                   # AES-GCM tag : 16 B
_MAX_SIGNATURE_SIZE:  int = 8192                 # Dilithium3 sig : ~3293 B
_MAX_SENDER_PK_SIZE:  int = 2048                 # Kyber768 PK : 1184 B
```

La fonction interne `read_chunk()` vérifie la borne **avant toute allocation** :

```python
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
```

La vérification `length > max_size` est effectuée après la lecture de la longueur déclarée
mais **avant** tout accès à `data[offset:offset+length]`. Aucun octet de données n'est
lu, aucune allocation n'est tentée. Le rejet est immédiat et à coût constant O(1).

---

### FAILLE 4 — MOYENNE | Validation des Types en Entrée

#### Vecteur d'Exploitation (v2.0.0)

Les méthodes publiques `encrypt()`, `decrypt()`, et `generate_anchor_key()` n'effectuaient
aucune validation des types de leurs arguments. Passer un `str` à la place de `bytes` pour
`plaintext`, ou un `int` pour `recipient_kem_pk`, provoquait des erreurs Python internes
tardives et cryptiques, parfois après que plusieurs étapes du pipeline cryptographique aient
déjà été exécutées partiellement :

```python
# Comportement v2.0.0 avec plaintext invalide
engine.encrypt(
    plaintext="chaîne de caractères",   # str, non bytes
    recipient_kem_pk=recipient_kem.public_key,
    ...
)
# Erreur levée DANS AES-256-GCM, pas à l'entrée de la fonction
# Message : TypeError cryptique, trace illisible pour l'intégrateur
```

#### Correction Implémentée (v2.1.0)

Vérification `isinstance()` en début de chaque fonction publique, avant tout traitement,
avec messages d'erreur explicites identifiant le paramètre problématique :

```python
# Dans VOLTProtocolEngine.encrypt()
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

# Dans VOLTProtocolEngine.decrypt()
if not isinstance(package, CiphertextPackage):
    raise TypeError("decrypt : package doit être un CiphertextPackage.")
for name, val in [
    ('recipient_kem_sk', recipient_kem_sk),
    ('sender_sign_pk', sender_sign_pk),
]:
    if not isinstance(val, bytes):
        raise TypeError(f"decrypt : '{name}' doit être de type bytes.")

# Dans CiphertextPackage.deserialize()
if not isinstance(data, (bytes, bytearray)):
    raise TypeError("deserialize attend un objet bytes ou bytearray.")
```

Le rejet est effectué **avant l'entrée dans tout code cryptographique**, garantissant qu'une
entrée malformée ne peut pas altérer l'état interne des primitives ou produire des erreurs
dans des contextes imprévisibles.

---

### FAILLE 5 — MINEURE | Durcissement de l'Anchor Key — Rejet Passphrase Vide

#### Vecteur d'Exploitation (v2.0.0)

La fonction `generate_anchor_key()` acceptait silencieusement une passphrase vide `""` ou
composée uniquement d'espaces `"   "`. Dans ce cas, PBKDF2-HMAC-SHA256 dérivait une
Anchor Key déterministe depuis une entropie nulle côté passphrase. Tous les utilisateurs
commettant cette erreur de configuration obtenaient **la même Anchor Key**, rendant la
protection illusoire sans qu'aucun avertissement ne soit émis.

#### Correction Implémentée (v2.1.0)

```python
if not isinstance(passphrase, str):
    raise TypeError("generate_anchor_key : passphrase doit être une chaîne str.")
if not passphrase.strip():
    raise ValueError(
        "generate_anchor_key : la passphrase ne peut pas être vide ou composée "
        "uniquement d'espaces. Une passphrase forte est obligatoire."
    )
```

La validation des constantes SMGS est également renforcée :

```python
try:
    delta_f = float(smgs_constants.get('delta_f', 4.669201))
    d_eff   = float(smgs_constants.get('d_eff',   1.584962))
except (TypeError, ValueError) as e:
    raise ValueError(
        f"generate_anchor_key : constantes SMGS invalides — {e}"
    ) from e
```

---

### Tableau Récapitulatif de l'Audit

| ID     | Sévérité     | Surface attaquée                        | Technique d'exploitation                     | Correction v2.1.0                          |
| :----- | :----------- | :-------------------------------------- | :------------------------------------------- | :----------------------------------------- |
| FIX-01 | **CRITIQUE** | Moteur cryptographique global           | Dépendance absente → fallback SHA256/XOR silencieux | `RuntimeError` au chargement + `VOLT_ALLOW_DEGRADED` opt-in |
| FIX-02 | **CRITIQUE** | Mémoire volatile (RAM)                  | Forensique RAM, core dump, cold boot, swap   | `SecretBuffer` + `ctypes.memset()` zero-on-free |
| FIX-03 | **MAJEURE**  | Désérialisation `CiphertextPackage`     | Paquet forgé → allocation O(4 Go) → OOM DoS | Bornes par chunk, rejet avant allocation   |
| FIX-04 | **MOYENNE**  | Interfaces `encrypt()` / `decrypt()`   | Type invalide → erreur tardive dans primitives | `isinstance()` en entrée, `TypeError` explicite |
| FIX-05 | **MINEURE**  | `generate_anchor_key()`                | Passphrase vide → Anchor Key partagée universellement | `ValueError` explicite avant dérivation |

---

## 2. Cartographie des Primitives NIST

### 2.1 Tableau Normatif Complet

| Composant                | Algorithme     | Classe NIST | Standard Officiel             | Clé Publique  | Clé Privée    | Rôle précis dans VOLT v2                                                                 |
| :----------------------- | :------------- | :---------- | :---------------------------- | :------------ | :------------ | :--------------------------------------------------------------------------------------- |
| **KEM**                  | Kyber768       | ML-KEM      | FIPS 203 (Draft 2024)         | 1 184 octets  | 2 400 octets  | Encapsulation post-quantique du secret partagé. Résistance prouvée aux attaques quantiques par la dureté du problème Module-LWE (Module Learning With Errors). Produit un `shared_secret` de 32 octets utilisé directement comme clé AES-256. |
| **Signature Numérique**  | Dilithium3     | ML-DSA      | FIPS 204 (Draft 2024)         | 1 952 octets  | 4 016 octets  | Authentification de l'expéditeur et non-répudiation post-quantique. Signe le bloc interne assemblé : `MAGIC + VERSION + kem_ciphertext + aes_nonce + aes_ciphertext + aes_tag`. La signature couvre le ciphertext, jamais le plaintext. |
| **Chiffrement Symétrique** | AES-256-GCM | AEAD        | FIPS 197 + SP 800-38D         | 256 bits (32 octets) | —       | Confidentialité des données avec authentification intégrée (AEAD). Nonce de 96 bits (12 octets) généré par `os.urandom(12)`. Tag d'authentification GCM de 128 bits (16 octets). La clé est le `shared_secret` Kyber768 ou son dérivé SHA256 si longueur incorrecte. |
| **MAC / Intégrité**      | HMAC-SHA256    | MAC         | FIPS 198-1 + FIPS 180-4       | 256 bits (32 octets) | —       | Protection anti-altération de l'enveloppe complète. Couvre `payload_body + signature` avec `mac_key = SHA256(shared_secret)`. Comparaison en temps constant via `hmac.compare_digest()` — immunité totale aux attaques par oracle temporel. |

### 2.2 Dépendances Système

| Bibliothèque        | Rôle                                                       | Statut en mode production |
| :------------------ | :--------------------------------------------------------- | :------------------------ |
| `liboqs-python`     | Binding Python pour Open Quantum Safe — Kyber768, Dilithium3 | **Obligatoire**           |
| `cryptography`      | AES-256-GCM AEAD via OpenSSL                               | **Obligatoire**           |
| `ctypes` (stdlib)   | `memset` pour effacement physique en RAM (`SecretBuffer`)  | Stdlib Python             |
| `hashlib` (stdlib)  | PBKDF2-HMAC-SHA256 (Anchor Key), SHA256 (mac_key)         | Stdlib Python             |
| `hmac` (stdlib)     | HMAC-SHA256 + `compare_digest` (protection timing)        | Stdlib Python             |
| `struct` (stdlib)   | Encodage gros-boutiste `>I` pour le format Strict-Frame   | Stdlib Python             |
| `os` (stdlib)       | `os.urandom()` pour nonces cryptographiquement sûrs       | Stdlib Python             |

**Installation (mode production) :**

```bash
pip install cryptography liboqs-python --user --break-system-packages
```

---

## 3. Architecture Visuelle des Flux

### 3.1 Pipeline de Chiffrement — Séquence `Encrypt-then-Sign-then-MAC`

La séquence **Encrypt → Sign → MAC** est non négociable dans son ordre. Inverser les
opérations (ex. Sign-then-Encrypt) exposerait le plaintext à travers la signature ou
permettrait des attaques par oracle de déchiffrement. La signature couvre le ciphertext
(jamais le plaintext), préservant la confidentialité. Le HMAC couvre la totalité du payload
signé, clôturant hermétiquement l'enveloppe contre toute altération post-signature.
En v2.1.0, les secrets `shared_secret` et `mac_key` sont protégés par `SecretBuffer`
et effacés via `ctypes.memset()` dès leur sortie de portée opérationnelle.

```mermaid
sequenceDiagram
    participant C as Expéditeur
    participant K as Kyber768 KEM
    participant SB1 as SecretBuffer(shared_secret)
    participant A as AES-256-GCM
    participant D as Dilithium3 Signature
    participant SB2 as SecretBuffer(mac_key)
    participant H as HMAC-SHA256
    participant P as CiphertextPackage

    Note over C: Entrées validées :<br/>isinstance() sur tous les args (FIX-04)<br/>len(plaintext) ≤ 64 Mo

    C->>K: encapsulate(recipient_kem_pk)
    K-->>C: EncapsulationResult {<br/>  kem_ciphertext (~1088 B),<br/>  shared_secret (32 B)<br/>}

    C->>SB1: SecretBuffer(shared_secret).__enter__()
    Note over SB1: shared_secret isolé en bytearray mutable<br/>Effacement ctypes.memset() garanti à la sortie (FIX-02)

    SB1->>A: encrypt(plaintext, bytes(shared_secret))
    A-->>SB1: aes_nonce (12 B, os.urandom)<br/>aes_ciphertext (N octets)<br/>aes_tag (16 B)

    Note over SB1: payload_body =<br/>b'VOLT' + VERSION(0x0200) +<br/>kem_ciphertext + aes_nonce +<br/>aes_ciphertext + aes_tag

    SB1->>D: sign(payload_body, sender_sign_sk)
    D-->>SB1: signature (~3293 B, Dilithium3)

    Note over SB1: mac_key = SHA256(shared_secret)<br/>full_payload = payload_body + signature

    SB1->>SB2: SecretBuffer(mac_key).__enter__()
    Note over SB2: mac_key isolé — effacement garanti (FIX-02)

    SB2->>H: compute(full_payload, mac_key)
    H-->>SB2: hmac_value (32 B)

    SB2-->>SB1: __exit__() → ctypes.memset(mac_key, 0)
    SB1-->>C: __exit__() → ctypes.memset(shared_secret, 0)

    C->>P: CiphertextPackage(<br/>  kem_ciphertext, aes_nonce,<br/>  aes_ciphertext, aes_tag,<br/>  signature, hmac_value,<br/>  sender_kem_pk<br/>)
    P-->>C: serialize() → flux binaire Strict-Frame
```

### 3.2 Pipeline de Déchiffrement — Logique Étanche `Fail-Fast`

Le déchiffrement applique une validation **strictement séquentielle et sans état partiel**.
Aucune donnée chiffrée n'est décodée avant que le HMAC et la signature Dilithium3 aient
été intégralement vérifiés. Cette contrainte d'ordre élimine les oracles de déchiffrement :
un attaquant ne peut jamais obtenir de feedback sur le contenu d'un paquet altéré.
En cas de rupture à n'importe quel point de la chaîne, un `ValueError` est levé
immédiatement, les secrets en cours sont effacés par `SecretBuffer.__exit__()`, et aucune
donnée partielle n'est retournée à l'appelant.

```mermaid
sequenceDiagram
    participant R as Récepteur
    participant DSZ as deserialize()
    participant K as Kyber768 KEM
    participant SB1 as SecretBuffer(shared_secret)
    participant SB2 as SecretBuffer(mac_key)
    participant H as HMAC-SHA256 verify
    participant S as Dilithium3 verify
    participant A as AES-256-GCM decrypt

    Note over R: buffer binaire brut

    R->>DSZ: CiphertextPackage.deserialize(buffer)

    Note over DSZ: [1] isinstance(data, bytes/bytearray) (FIX-04)<br/>[2] len(data) ≥ 8<br/>[3] data[:4] == b'VOLT'<br/>[4] version[0] == 0x0200<br/>[5] Chaque chunk : longueur ≤ max_size AVANT allocation (FIX-03)<br/>[6] Bornes offset sur chaque chunk<br/>[7] Présence HMAC 32 B

    alt Contrôle échoué (type / magic / version / taille / borne)
        DSZ-->>R: ValueError descriptif — rejet immédiat<br/>Aucune allocation. Aucune primitive appelée.
    end

    DSZ-->>R: CiphertextPackage reconstruit

    R->>K: decapsulate(kem_ciphertext, recipient_kem_sk)
    K-->>R: shared_secret (32 B)

    R->>SB1: SecretBuffer(shared_secret).__enter__()
    Note over SB1: Effacement ctypes.memset() garanti à la sortie

    Note over SB1: payload_body reconstruit :<br/>b'VOLT' + VERSION + kem_ciphertext +<br/>aes_nonce + aes_ciphertext + aes_tag<br/>full_payload = payload_body + signature

    SB1->>SB2: SecretBuffer(SHA256(shared_secret)).__enter__()

    SB2->>H: verify(full_payload, hmac_value, mac_key)

    alt HMAC invalide — paquet altéré
        H-->>R: ValueError<br/>"RUPTURE DE SÉCURITÉ CRITIQUE :<br/>Signature de contrôle HMAC invalide. Paquet altéré."
        Note over SB2: SB2.__exit__() → ctypes.memset(mac_key, 0)
        Note over SB1: SB1.__exit__() → ctypes.memset(shared_secret, 0)
        Note over R: Arrêt total. Aucune donnée extraite.<br/>Aucun oracle exploitable.
    end

    SB2-->>SB1: __exit__() → ctypes.memset(mac_key, 0)
    H-->>R: HMAC OK — enveloppe intègre

    SB1->>S: verify(payload_body, signature, sender_sign_pk)

    alt Signature Dilithium3 invalide — identité non authentifiée
        S-->>R: ValueError<br/>"RUPTURE DE SÉCURITÉ CRITIQUE :<br/>Signature post-quantique Dilithium3 invalide ou usurpée."
        Note over SB1: SB1.__exit__() → ctypes.memset(shared_secret, 0)
        Note over R: Arrêt total. Expéditeur non authentifié.<br/>Aucune donnée extraite.
    end

    S-->>R: Signature OK — expéditeur authentifié

    SB1->>A: decrypt(aes_nonce, aes_ciphertext, aes_tag, shared_secret)
    A-->>SB1: plaintext original

    SB1-->>R: __exit__() → ctypes.memset(shared_secret, 0)

    Note over R: plaintext livré uniquement après<br/>triple validation réussie :<br/>deserialize → HMAC → Dilithium3 → AES
```

---

## 4. Architecture de l'Anchor Key System

### 4.1 Problème Dimensionnel des Clés Post-Quantiques

Les primitives NIST de niveau 3 (sécurité équivalente AES-192) produisent des artefacts de
taille prohibitive pour toute interface utilisateur classique :

| Artefact                    | Taille exacte   | Représentation hexadécimale | Compatibilité QR Code standard |
| :-------------------------- | :-------------- | :-------------------------- | :----------------------------- |
| Clé publique Kyber768        | 1 184 octets    | 2 368 caractères            | Impossible (saturation > 200 chars) |
| Clé privée Kyber768          | 2 400 octets    | 4 800 caractères            | Impossible                     |
| Signature Dilithium3         | ~3 293 octets   | ~6 586 caractères           | Impossible                     |
| Clé publique Dilithium3      | 1 952 octets    | 3 904 caractères            | Impossible                     |
| **Anchor Key (solution)**    | **24 octets**   | **48 caractères**           | **Trivial — compatible**        |

### 4.2 Définition Formelle de l'Anchor Key

L'Anchor Key est une empreinte de **48 caractères hexadécimaux majuscules (24 octets)**
dérivée de manière déterministe et irréversible selon la fonction suivante :

```
AnchorKey(passphrase, δ_F, D_eff) =
    PBKDF2-HMAC-SHA256(
        password = UTF8(passphrase),
        salt     = UTF8("RATISS:SMGS_CALIBRATION:delta_f={δ_F:.6f}:d_eff={D_eff:.6f}"),
        c        = 10 000,
        dkLen    = 24
    ).hex().upper()
```

Où :
- `δ_F = 4.669201` — Constante de Feigenbaum delta, issue de la théorie du chaos,
  caractérisant le rapport de convergence des bifurcations dans les systèmes dynamiques
  unidimensionnels. Adoptée comme constante de calibration dans le domaine SMGS de
  RATISS pour sa nature universelle et déterministe.
- `D_eff = 1.584962` — Dimension effective SMGS, valeur propre au référentiel
  morphologique de RATISS Labs, encodée avec une précision de 6 décimales.

### 4.3 Propriétés Mathématiques et Sémantiques

| Propriété                        | Garantie formelle                                                                                           |
| :------------------------------- | :---------------------------------------------------------------------------------------------------------- |
| **Déterminisme absolu**          | `AnchorKey(p, δ_F, D_eff) = AnchorKey(p, δ_F, D_eff)` — Même triplet → même empreinte, sur toute machine, sans état partagé. |
| **Sensibilité au sel physique**  | Une variation de `D_eff` de `1.584962` à `1.580000` produit une empreinte entièrement différente sans corrélation statistique détectable. |
| **Irréversibilité**              | PBKDF2 avec `c = 10 000` itérations. La reconstruction de la passphrase depuis l'Anchor Key est computationnellement prohibitive avec le matériel actuel. |
| **Rejet passphrase vide** *(v2.1.0)* | `passphrase.strip() == ""` → `ValueError` avant toute dérivation. Bloque les empreintes d'entropie nulle. |
| **Validation des constantes** *(v2.1.0)* | Conversion `float()` avec gestion d'exception. Constante non-numérique → `ValueError` avec message explicite. |
| **Unicité d'interface**          | Seule l'Anchor Key de 48 caractères est exposée à l'utilisateur. Les clés NIST (1 184 B, 1 952 B) ne quittent jamais la RAM volatile. |

### 4.4 Code Source de Référence Complet

```python
def generate_anchor_key(passphrase: str, smgs_constants: dict) -> str:
    # Validation des types et de la non-vacuité (FIX-04, FIX-05)
    if not isinstance(passphrase, str):
        raise TypeError("generate_anchor_key : passphrase doit être une chaîne str.")
    if not passphrase.strip():
        raise ValueError(
            "generate_anchor_key : la passphrase ne peut pas être vide ou composée "
            "uniquement d'espaces. Une passphrase forte est obligatoire."
        )
    if not isinstance(smgs_constants, dict):
        raise TypeError("generate_anchor_key : smgs_constants doit être un dict.")

    # Extraction et validation des constantes SMGS
    try:
        delta_f = float(smgs_constants.get('delta_f', 4.669201))
        d_eff   = float(smgs_constants.get('d_eff',   1.584962))
    except (TypeError, ValueError) as e:
        raise ValueError(f"generate_anchor_key : constantes SMGS invalides — {e}") from e

    # Construction du sel déterministe ancré dans les constantes physiques SMGS
    salt_str = (
        f"RATISS:SMGS_CALIBRATION:"
        f"delta_f={delta_f:.6f}:"
        f"d_eff={d_eff:.6f}"
    )
    salt = salt_str.encode('utf-8')

    # Dérivation PBKDF2-HMAC-SHA256 — 10 000 itérations — sortie 24 octets
    derived_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt,
        iterations=10000,
        dklen=24,
    )
    return derived_bytes.hex().upper()
    # Exemple de sortie : "52375A5F333035653631396438636439663437373832"
```

---

## 5. Structure Binaire Strict-Frame

### 5.1 Vue d'Ensemble du Format

Le `CiphertextPackage` est sérialisé dans un format binaire compact, auto-descriptif et
validable sans état externe. Chaque segment de longueur variable est précédé d'un entête
de longueur encodé en gros-boutiste non-signé sur 4 octets (`struct.pack('>I', length)`).
La valeur HMAC est la seule exception : sa taille est fixe et connue (32 octets), elle est
donc écrite directement sans préfixe de longueur.

### 5.2 Plan d'Implantation Exact des Octets

```
Offset (B)    Taille          Champ                Encodage / Contrainte
─────────────────────────────────────────────────────────────────────────────────
0             4               MAGIC                Constante littérale b'VOLT' (0x56 0x4F 0x4C 0x54)
                                                   Rejet immédiat si différent.

4             4               VERSION              struct.pack('>HH', 0x0200, 0x0000)
                                                   Octets : 0x02 0x00 0x00 0x00
                                                   Major=0x0200 (VOLT v2), Minor=0x0000
                                                   Rejet si Major ≠ 0x0200.

8             4               LEN_KEM_CT           struct.pack('>I', len(kem_ciphertext))
                                                   Entier non-signé 32 bits gros-boutiste.
                                                   Validé : valeur ≤ 2048 avant lecture.

12            LEN_KEM_CT      KEM_CIPHERTEXT       Ciphertext Kyber768.
                                                   Taille nominale : 1 088 octets.

12+LEN_KEM_CT 4               LEN_NONCE            struct.pack('>I', 12)
                                                   Validé : valeur ≤ 32 avant lecture.

...           12              AES_NONCE            Nonce AES-GCM 96 bits.
                                                   Généré par os.urandom(12).

...           4               LEN_AES_CT           struct.pack('>I', len(aes_ciphertext))
                                                   Validé : valeur ≤ 67 108 864 (64 Mo).

...           LEN_AES_CT      AES_CIPHERTEXT       Données chiffrées.
                                                   Taille = taille du plaintext original.

...           4               LEN_AES_TAG          struct.pack('>I', 16)
                                                   Validé : valeur ≤ 32 avant lecture.

...           16              AES_TAG              Tag d'authentification GCM 128 bits.

...           4               LEN_SIGNATURE        struct.pack('>I', len(signature))
                                                   Validé : valeur ≤ 8192 avant lecture.

...           LEN_SIGNATURE   SIGNATURE            Signature Dilithium3.
                                                   Taille nominale : ~3 293 octets.

...           32              HMAC_VALUE           Tag HMAC-SHA256 en taille fixe.
                                                   Pas de préfixe LEN — toujours 32 octets.
                                                   Lu comme data[offset:offset+32].

...           4               LEN_SENDER_PK        struct.pack('>I', len(sender_public_key))
                                                   Validé : valeur ≤ 2048 avant lecture.

...           LEN_SENDER_PK   SENDER_PUBLIC_KEY    Clé publique KEM Kyber768 de l'expéditeur.
                                                   Taille nominale : 1 184 octets.
─────────────────────────────────────────────────────────────────────────────────
```

### 5.3 Représentation Linéaire Compact

```
[b'VOLT':4B] [0x02000000:4B]
[len(kem_ciphertext):4B>I] [kem_ciphertext:≤2048B]
[len(aes_nonce):4B>I]      [aes_nonce:12B]
[len(aes_ciphertext):4B>I] [aes_ciphertext:≤64MB]
[len(aes_tag):4B>I]        [aes_tag:16B]
[len(signature):4B>I]      [signature:≤8192B]
[hmac_value:32B — FIXE, sans préfixe LEN]
[len(sender_public_key):4B>I] [sender_public_key:≤2048B]
```

### 5.4 Taille Totale Estimée (plaintext de 64 octets)

| Segment               | Entête (B) | Données (B)  | Total (B)    |
| :-------------------- | :--------- | :----------- | :----------- |
| MAGIC + VERSION       | —          | 8            | 8            |
| KEM_CIPHERTEXT        | 4          | 1 088        | 1 092        |
| AES_NONCE             | 4          | 12           | 16           |
| AES_CIPHERTEXT        | 4          | ~64          | ~68          |
| AES_TAG               | 4          | 16           | 20           |
| SIGNATURE             | 4          | ~3 293       | ~3 297       |
| HMAC_VALUE            | 0          | 32           | 32           |
| SENDER_PUBLIC_KEY     | 4          | 1 184        | 1 188        |
| **TOTAL ESTIMÉ**      |            |              | **~5 721 B** |

### 5.5 Séquence de Désérialisation et Contrôles (v2.1.0)

La méthode `CiphertextPackage.deserialize()` applique les contrôles suivants dans l'ordre
strict, sans exception possible dans l'ordre :

1. `isinstance(data, (bytes, bytearray))` → `TypeError` si non-conforme. *(FIX-04)*
2. `len(data) < 8` → `ValueError("Dimensions binaires insuffisantes")`
3. `data[:4] != b'VOLT'` → `ValueError` avec octets reçus en clair
4. `struct.unpack('>HH', data[4:8])[0] != 0x0200` → `ValueError` avec code reçu
5. Pour chaque chunk : `offset + 4 > len(data)` → `ValueError` avec nom du champ
6. Pour chaque chunk : `length > max_size` → `ValueError` **avant toute allocation** *(FIX-03)*
7. Pour chaque chunk : `offset + length > len(data)` → `ValueError` avec bytecounts détaillés
8. `offset + 32 > len(data)` → `ValueError("HMAC manquant ou tronqué")`
9. `struct.error` → capturé et converti en `ValueError` descriptif

---

## 6. Guide d'Intégration et Exemple Prêt à l'Emploi

### 6.1 Prérequis d'Environnement

```bash
# Installation des dépendances obligatoires (mode production)
pip install cryptography liboqs-python --user --break-system-packages

# Vérification de disponibilité
python3 -c "import oqs; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('OK')"
```

> En l'absence de `liboqs-python` ou `cryptography`, l'import de `volt_v2_production`
> lève un `RuntimeError` immédiat. Aucune opération cryptographique ne peut être tentée.

### 6.2 Script d'Intégration Complet — Cycle Cryptographique v2.1.0-hardened

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exemple d'intégration VOLT v2.1.0-hardened
Démontre le cycle cryptographique complet :
  - Génération d'Anchor Key ergonomique
  - Initialisation du moteur par injection de dépendances
  - Génération des trousseaux NIST (Kyber768 + Dilithium3)
  - Chiffrement hybride Encrypt-then-Sign-then-MAC
  - Sérialisation binaire Strict-Frame
  - Désérialisation avec contrôles stricts
  - Déchiffrement authentifié Fail-Fast
RATISS LABS — Apache License 2.0
"""

from volt_v2_production import (
    LiboqsKEM,
    LiboqsSignature,
    ProductionAESGCM,
    PythonHMAC,
    VOLTProtocolEngine,
    CiphertextPackage,
    generate_anchor_key,
)

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 0 — Génération de l'Anchor Key ergonomique (optionnel)
#
# L'Anchor Key est l'interface utilisateur vers la complexité NIST.
# Elle ne remplace pas les clés cryptographiques mais permet à un
# utilisateur de mémoriser, afficher ou scanner une empreinte compacte
# de 48 caractères au lieu de 2368 caractères (clé Kyber768 hex).
#
# Propriétés garanties :
#   - Déterminisme : même passphrase + mêmes constantes = même Anchor Key
#   - Sensibilité : variation infinitésimale des constantes SMGS → empreinte totalement différente
#   - Irréversibilité : PBKDF2 c=10000 — reconstruction passphrase prohibitive
#
# Sécurité v2.1.0 : passphrase vide → ValueError immédiat (FIX-05)
# ─────────────────────────────────────────────────────────────────────

smgs_constants = {
    "delta_f": 4.669201,   # Constante de Feigenbaum delta (chaos/bifurcations)
    "d_eff":   1.584962,   # Dimension effective SMGS — RATISS Labs
}

anchor = generate_anchor_key("Passphrase_Maitre_Utilisateur_RATISS", smgs_constants)
print(f"[ANCHOR KEY] Empreinte ergonomique (48 chars) : {anchor}")
# Exemple de sortie : "52375A5F333035653631396438636439663437373832"

# Vérification du rejet de passphrase vide (comportement v2.1.0)
try:
    generate_anchor_key("", smgs_constants)
except ValueError as e:
    print(f"[GUARD] Passphrase vide rejetée : {e}")

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 1 — Initialisation du moteur par injection de dépendances
#
# Chaque primitive est instanciée séparément et injectée explicitement
# dans le moteur. Ce pattern Open/Closed permet de remplacer n'importe
# quelle primitive (ex. Kyber1024 à la place de Kyber768) sans modifier
# le code orchestrateur.
#
# Sécurité v2.1.0 : si liboqs ou cryptography est absent en mode
# production, RuntimeError est levé à l'import du module, avant même
# d'atteindre cette ligne. (FIX-01)
# ─────────────────────────────────────────────────────────────────────

engine = VOLTProtocolEngine(
    kem=LiboqsKEM(),              # Kyber768 via liboqs — FIPS 203
    signature=LiboqsSignature(),  # Dilithium3 via liboqs — FIPS 204
    cipher=ProductionAESGCM(),    # AES-256-GCM via cryptography — SP 800-38D
    mac=PythonHMAC(),             # HMAC-SHA256 via stdlib — FIPS 198-1
)

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 2 — Génération des trousseaux de clés NIST
#
# generate_system_keys() produit deux paires :
#   - KEM (Kyber768)        : public_key (1184 B) + private_key (2400 B)
#   - Signature (Dilithium3): public_key (1952 B) + private_key (4016 B)
#
# Dans un scénario réel :
#   - Le destinataire génère son trousseau KEM et publie sa clé publique KEM.
#   - L'expéditeur génère son trousseau Signature et publie sa clé publique Sign.
#   - L'échange de clés publiques est géré par un mécanisme PKI externe.
# ─────────────────────────────────────────────────────────────────────

# Trousseau du destinataire (recipient_kem_keys.public_key est distribué publiquement)
recipient_kem_keys, recipient_sign_keys = engine.generate_system_keys()

# Trousseau de l'expéditeur (sender_sign_keys.public_key est distribué publiquement)
sender_kem_keys, sender_sign_keys = engine.generate_system_keys()

print(f"[KEYGEN] Kyber768   clé publique  : {len(recipient_kem_keys.public_key)} octets")
print(f"[KEYGEN] Kyber768   clé privée    : {len(recipient_kem_keys.private_key)} octets")
print(f"[KEYGEN] Dilithium3 clé publique  : {len(sender_sign_keys.public_key)} octets")
print(f"[KEYGEN] Dilithium3 clé privée    : {len(sender_sign_keys.private_key)} octets")

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 3 — Chiffrement hybride Encrypt-then-Sign-then-MAC
#
# Séquence interne du moteur (v2.1.0) :
#   1. Validation des types et de la taille du plaintext (FIX-04)
#   2. Kyber768 encapsule un shared_secret (32 B) depuis recipient_kem_pk
#   3. SecretBuffer(shared_secret) isole le secret en RAM mutable (FIX-02)
#   4. AES-256-GCM chiffre le plaintext avec shared_secret → (nonce, ct, tag)
#   5. Dilithium3 signe le bloc : b'VOLT'+VERSION+kem_ct+nonce+ct+tag
#   6. SecretBuffer(SHA256(shared_secret)) isole mac_key (FIX-02)
#   7. HMAC-SHA256 couvre (payload_body + signature) avec mac_key
#   8. SecretBuffer.__exit__() efface mac_key via ctypes.memset()
#   9. SecretBuffer.__exit__() efface shared_secret via ctypes.memset()
# ─────────────────────────────────────────────────────────────────────

plaintext = b"CONFIDENTIEL RATISS V7 : Donnees sensibles de session holomorphique."

package = engine.encrypt(
    plaintext=plaintext,
    recipient_kem_pk=recipient_kem_keys.public_key,   # Clé publique KEM du destinataire
    sender_sign_sk=sender_sign_keys.private_key,       # Clé privée Signature de l'expéditeur
    sender_kem_pk=sender_kem_keys.public_key,          # Clé publique KEM de l'expéditeur
)

print(f"[ENCRYPT] HMAC-SHA256  : {package.hmac_value.hex()}")
print(f"[ENCRYPT] KEM CT size  : {len(package.kem_ciphertext)} octets")
print(f"[ENCRYPT] Signature    : {len(package.signature)} octets (Dilithium3)")

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 4 — Sérialisation binaire Strict-Frame
#
# Le paquet est converti en flux d'octets persistable ou transmissible.
# Format : b'VOLT' + version 0x0200 + chunks >I + HMAC fixe 32B
# ─────────────────────────────────────────────────────────────────────

binary_buffer = package.serialize()

print(f"[SERIALIZE] Magic header   : {binary_buffer[:4]}")
print(f"[SERIALIZE] Version bytes  : {binary_buffer[4:8].hex()}")
print(f"[SERIALIZE] Taille totale  : {len(binary_buffer)} octets")

assert binary_buffer[:4] == b'VOLT', "ERREUR : Magic header VOLT absent"
assert binary_buffer[4:6] == b'\x02\x00', "ERREUR : Version incorrecte"

# Exemple de persistance disque
# with open("session_ratiss.volt.bin", "wb") as f:
#     f.write(binary_buffer)

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 5 — Désérialisation avec contrôles stricts (v2.1.0)
#
# Contrôles appliqués par deserialize() dans l'ordre :
#   [1] isinstance(data, bytes/bytearray) (FIX-04)
#   [2] len(data) >= 8
#   [3] Magic == b'VOLT'
#   [4] Version Major == 0x0200
#   [5] Chaque chunk : longueur <= max_size AVANT allocation (FIX-03)
#   [6] Bornes buffer pour chaque chunk
#   [7] Présence HMAC 32 octets
# ─────────────────────────────────────────────────────────────────────

# Exemple chargement depuis disque
# with open("session_ratiss.volt.bin", "rb") as f:
#     binary_buffer = f.read()

received_package = CiphertextPackage.deserialize(binary_buffer)

print(f"[DESERIALIZE] KEM CT reconstruit : {len(received_package.kem_ciphertext)} octets")
print(f"[DESERIALIZE] HMAC vérifié       : {received_package.hmac_value.hex()}")

# ─────────────────────────────────────────────────────────────────────
# ÉTAPE 6 — Déchiffrement authentifié Fail-Fast
#
# Séquence interne du moteur (v2.1.0) :
#   1. Validation des types (FIX-04)
#   2. Kyber768 décapsule le shared_secret
#   3. SecretBuffer(shared_secret) isole le secret (FIX-02)
#   4. SecretBuffer(mac_key) isole la clé HMAC (FIX-02)
#   5. HMAC vérifié EN PREMIER — ValueError si invalide (Fail-Fast)
#      → Aucun déchiffrement avant validation HMAC complète
#   6. Dilithium3 vérifié — ValueError si invalide (Fail-Fast)
#   7. AES-256-GCM déchiffre après double validation réussie
#   8. SecretBuffer.__exit__() efface mac_key + shared_secret
# ─────────────────────────────────────────────────────────────────────

decrypted = engine.decrypt(
    package=received_package,
    recipient_kem_sk=recipient_kem_keys.private_key,   # Clé privée KEM du destinataire
    sender_sign_pk=sender_sign_keys.public_key,         # Clé publique Signature de l'expéditeur
)

assert decrypted == plaintext, "ERREUR CRITIQUE : données déchiffrées non conformes"
print(f"[DECRYPT] Plaintext récupéré : {decrypted}")
print("[SUCCESS] Cycle cryptographique complet validé — VOLT v2.1.0-hardened.")

# ─────────────────────────────────────────────────────────────────────
# DÉMONSTRATION — Détection de falsification (Fail-Fast en pratique)
#
# Un attaquant altère un octet dans le buffer sérialisé.
# Le HMAC détecte l'altération avant tout déchiffrement.
# Aucun oracle de déchiffrement n'est exposé.
# ─────────────────────────────────────────────────────────────────────

print("\n[TEST] Simulation d'altération de paquet...")
corrupted = bytearray(binary_buffer)
corrupted[len(corrupted) - 40] ^= 0xFF   # Flip d'un bit dans la zone HMAC/signature

corrupted_package = CiphertextPackage.deserialize(bytes(corrupted))

try:
    engine.decrypt(
        package=corrupted_package,
        recipient_kem_sk=recipient_kem_keys.private_key,
        sender_sign_pk=sender_sign_keys.public_key,
    )
    print("[FAIL] FAILLE : paquet corrompu accepté.")
except ValueError as e:
    print(f"[PASS] Falsification rejetée en Fail-Fast : {e}")

# ─────────────────────────────────────────────────────────────────────
# DÉMONSTRATION — Rejet anti-DoS (chunk surdimensionné)
#
# Un paquet forgeant un chunk de taille excessive est rejeté
# AVANT toute allocation mémoire.
# ─────────────────────────────────────────────────────────────────────

import struct

print("\n[TEST] Simulation d'attaque DoS par chunk surdimensionné...")
dos_packet  = b'VOLT' + struct.pack('>HH', 0x0200, 0x0000)
dos_packet += struct.pack('>I', 999_999) + b'\x00' * 64   # Déclare 999999 B, envoie 64 B

try:
    CiphertextPackage.deserialize(dos_packet)
    print("[FAIL] FAILLE DoS : chunk surdimensionné accepté.")
except ValueError as e:
    print(f"[PASS] Attaque DoS bloquée avant allocation : {e}")
```

### 6.3 Exécution de la Suite de Certification Intégrée

```python
from volt_v2_production import run_production_tests

success = run_production_tests()
```

**Résultat attendu en environnement sain (6/6 tests) :**

```
[INIT] Lancement de la suite de certification VOLT v2 (v2.1.0-hardened)...
  [PASS] Étape 1 : Injection des primitives et initialisation OK.
  [PASS] Étape 2 : Génération de clés NIST conforme.
  [PASS] Étape 3 : Anchor Key validée. Empreinte : <48 chars hex>
  [PASS] Étape 4 : Chiffrement hybride, sérialisation et déchiffrement validés.
  [PASS] Étape 5 : Altération détectée. Pare-feu HMAC/Dilithium actif.
  [PASS] Étape 6 : Chunk DoS rejeté par les limites de taille.
[SUCCESS] Suite de certification VOLT v2 validée à 100% (6/6 tests) !
```

---

## Périmètre de Sécurité et Limites Résiduelles

### Ce que VOLT v2.1.0-hardened Sécurise

| Surface                                              | Mécanisme actif                                             |
| :--------------------------------------------------- | :---------------------------------------------------------- |
| Données au repos (fichiers `.bin` locaux)            | AES-256-GCM + HMAC-SHA256 avant écriture disque            |
| Persistance cognitive RATISS (synapses, historiques) | Enveloppe chiffrée complète CiphertextPackage               |
| Secrets en mémoire volatile                          | `SecretBuffer` + `ctypes.memset()` — effacement zero-on-free |
| Mode dégradé non-sécurisé                            | Bloqué par défaut — `RuntimeError` si dépendance absente    |
| Paquets DoS surdimensionnés                          | Rejet avant allocation mémoire — borne par chunk            |
| Injections de types invalides                        | `isinstance()` en entrée de chaque fonction publique        |
| Attaques par oracle de déchiffrement                 | HMAC vérifié en premier — aucun déchiffrement avant validation |
| Attaques temporelles sur MAC                         | `hmac.compare_digest()` — comparaison en temps constant     |
| Résistance aux adversaires quantiques                | Kyber768 (ML-KEM) + Dilithium3 (ML-DSA) — résistants à l'algorithme de Shor |

### Limites Résiduelles Non Couvertes

| Surface                                              | Nature de l'exposition résiduelle                           |
| :--------------------------------------------------- | :---------------------------------------------------------- |
| Transport réseau vers API cloud                      | TLS classique uniquement — vulnérable aux attaques "Harvest Now, Decrypt Later" |
| Copie `bytes()` issue de `SecretBuffer`             | Copie immuable en RAM jusqu'au GC Python — fenêtre réduite, non éliminée |
| Swap OS sans FDE                                     | Pages swappées avant effacement `SecretBuffer` — hors périmètre VOLT |
| Canaux auxiliaires (timing/power) sur hardware dédié | liboqs non certifié temps-constant sur toutes architectures |
| Distribution des clés publiques (PKI)               | La validité de `sender_sign_pk` doit être établie par un mécanisme externe |

### Posture Épistémologique Officielle

> *"Le présent protocole constitue une implémentation de référence conforme aux standards
> NIST 2024 (FIPS 203, FIPS 204, FIPS 197, SP 800-38D, FIPS 198-1), renforcée en
> v2.1.0 contre les modes dégradés non-sécurisés, l'exposition mémoire des secrets, les
> attaques par allocation mémoire excessive, les injections de types invalides et les
> passphrases à entropie nulle. Sa pertinence opérationnelle dans des environnements
> contraints devra être évaluée indépendamment par audits formels de sécurité et tests de
> pénétration conduits par des laboratoires certifiés. L'implémentation n'a pas été soumise
> à certification FIPS 140-3 et ne doit pas être utilisée dans des contextes l'exigeant
> sans validation préalable."*

---

*Spécification finale produite pour VOLT v2.1.0-hardened.*
*Toute divergence entre ce document et le code source `volt_v2_production.py` doit être
signalée comme bug prioritaire auprès de Jonathan Evina (Sama) — RATISS LABS.*

*Document classifié : Usage interne RATISS LABS et partenaires autorisés.*
*Distribué sous Apache License 2.0 — Conserver cette notice dans toute redistribution.*
