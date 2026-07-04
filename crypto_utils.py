from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# ---------- Fernet (symmetric) encryption - used for the actual file contents ----------

def generate_symmetric_key():
    """
    Generates a new Fernet key (AES-128 under the hood, with built-in integrity checking).
    This key encrypts/decrypts the actual file data.
    """
    return Fernet.generate_key()


def encrypt_file(file_bytes, key):
    """Encrypts raw file bytes using the given Fernet key."""
    f = Fernet(key)
    return f.encrypt(file_bytes)


def decrypt_file(encrypted_bytes, key):
    """
    Decrypts bytes that were encrypted with the same Fernet key.
    Raises InvalidToken if the key is wrong or the data was tampered with.
    """
    f = Fernet(key)
    return f.decrypt(encrypted_bytes)


# ---------- RSA key-wrapping (envelope encryption) - protects the Fernet key itself ----------

def load_public_key(path="master_public_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path="master_private_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def wrap_key(fernet_key, public_key=None):
    """
    Encrypts ('wraps') a Fernet key using the RSA public key.
    This is what actually gets stored in the database - never the raw Fernet key.
    """
    if public_key is None:
        public_key = load_public_key()

    wrapped = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped


def unwrap_key(wrapped_key, private_key=None):
    """
    Decrypts ('unwraps') a stored wrapped key back into a usable Fernet key,
    using the RSA private key. Only someone with the private key can do this.
    """
    if private_key is None:
        private_key = load_private_key()

    fernet_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return fernet_key