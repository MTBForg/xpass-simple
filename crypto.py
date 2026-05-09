"""
XPass Crypto Module — Per-User Zero-Knowledge Encryption

Key hierarchy:
  Master Password → (Argon2) → Master Key
  Master Key → encrypts User Encryption Key (UEK)
  UEK → encrypts Folder Keys
  Folder Keys → encrypt Credentials
  RSA Key Pair → enables sharing Folder Keys between users

All functions are stateless and operate on raw bytes/strings.
No database or Flask dependencies here.
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
KDF_ITERATIONS = 600_000
RSA_KEY_SIZE = 2048

# ---------------------------------------------------------------------------
# 1. Key Derivation — Master Key from password
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt (16 bytes)."""
    return os.urandom(16)


def derive_master_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte master key from a user's password using PBKDF2-HMAC-SHA256.
    Returns a Fernet-compatible base64-encoded key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def derive_auth_hash(password: str, salt: bytes) -> str:
    """
    Derive a separate authentication hash from the password.
    This is what gets compared on login — NOT the master key.
    Uses fewer iterations on a different salt so it's a completely
    independent derivation from the encryption master key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()


# ---------------------------------------------------------------------------
# 2. User Encryption Key (UEK) — symmetric key per user
# ---------------------------------------------------------------------------

def generate_user_encryption_key() -> bytes:
    """Generate a random Fernet-compatible user encryption key."""
    return Fernet.generate_key()


def encrypt_user_key(uek: bytes, master_key: bytes) -> bytes:
    """Encrypt the UEK with the master key (derived from password)."""
    f = Fernet(master_key)
    return f.encrypt(uek)


def decrypt_user_key(encrypted_uek: bytes, master_key: bytes) -> bytes:
    """Decrypt the UEK using the master key."""
    f = Fernet(master_key)
    return f.decrypt(encrypted_uek)


# ---------------------------------------------------------------------------
# 3. RSA Key Pair — for sharing folder keys between users
# ---------------------------------------------------------------------------

def generate_rsa_keypair() -> tuple:
    """
    Generate an RSA key pair.
    Returns (public_key_pem: bytes, private_key_pem: bytes)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem, private_pem


def encrypt_private_key(private_pem: bytes, master_key: bytes) -> bytes:
    """Encrypt the RSA private key PEM with the user's master key."""
    f = Fernet(master_key)
    return f.encrypt(private_pem)


def decrypt_private_key(encrypted_private: bytes, master_key: bytes) -> bytes:
    """Decrypt the RSA private key PEM using the user's master key."""
    f = Fernet(master_key)
    return f.decrypt(encrypted_private)


# ---------------------------------------------------------------------------
# 4. Folder Key — symmetric key per folder
# ---------------------------------------------------------------------------

def generate_folder_key() -> bytes:
    """Generate a random Fernet-compatible folder encryption key."""
    return Fernet.generate_key()


def encrypt_folder_key(folder_key: bytes, uek: bytes) -> bytes:
    """Encrypt a folder key with the user's UEK."""
    f = Fernet(uek)
    return f.encrypt(folder_key)


def decrypt_folder_key(encrypted_folder_key: bytes, uek: bytes) -> bytes:
    """Decrypt a folder key using the user's UEK."""
    f = Fernet(uek)
    return f.decrypt(encrypted_folder_key)


# ---------------------------------------------------------------------------
# 5. RSA envelope — wrap/unwrap folder keys for sharing
# ---------------------------------------------------------------------------

def wrap_folder_key_for_recipient(folder_key: bytes, recipient_public_pem: bytes) -> bytes:
    """
    Encrypt the folder key with the recipient's RSA public key.
    This creates the 'envelope' stored in SharedFolder.
    """
    public_key = serialization.load_pem_public_key(recipient_public_pem, backend=default_backend())
    return public_key.encrypt(
        folder_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_folder_key(envelope: bytes, private_pem: bytes) -> bytes:
    """
    Decrypt the folder key envelope using the recipient's RSA private key.
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
    return private_key.decrypt(
        envelope,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# 6. Credential encryption — encrypt/decrypt with folder key
# ---------------------------------------------------------------------------

def encrypt_credential(plaintext: str, folder_key: bytes) -> str:
    """Encrypt a credential password using the folder's key. Returns base64 string."""
    f = Fernet(folder_key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_credential(ciphertext: str, folder_key: bytes) -> str:
    """Decrypt a credential password using the folder's key."""
    f = Fernet(folder_key)
    return f.decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# 7. Export encryption — independent password-based encryption for exports
# ---------------------------------------------------------------------------

def derive_export_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from an export password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
