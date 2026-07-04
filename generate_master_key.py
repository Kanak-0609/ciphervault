from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    """
    Generates an RSA key pair. The private key stays secret and is used to
    'unwrap' (decrypt) Fernet keys. The public key is used to 'wrap' (encrypt)
    Fernet keys before they're stored in the database.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


if __name__ == "__main__":
    private_pem, public_pem = generate_rsa_keypair()

    with open("master_private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("master_public_key.pem", "wb") as f:
        f.write(public_pem)

    print("RSA key pair generated: master_private_key.pem, master_public_key.pem")