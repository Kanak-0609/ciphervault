from crypto_utils import (
    generate_symmetric_key, encrypt_file, decrypt_file,
    wrap_key, unwrap_key
)

# Step 1: Generate a Fernet key (this would normally happen per-key-record)
fernet_key = generate_symmetric_key()
print("Original Fernet key:", fernet_key)

# Step 2: Wrap it with RSA (this is what gets stored in the database)
wrapped = wrap_key(fernet_key)
print("\nWrapped key (safe to store):", wrapped[:50], "...")

# Step 3: Unwrap it back (this happens only when actually encrypting/decrypting a file)
unwrapped = unwrap_key(wrapped)
print("\nUnwrapped key:", unwrapped)

assert unwrapped == fernet_key
print("\nWrap/unwrap successful - keys match.")

# Step 4: Confirm the unwrapped key still works for actual file encryption
original_data = b"This is a secret message inside a file."
encrypted = encrypt_file(original_data, unwrapped)
decrypted = decrypt_file(encrypted, unwrapped)

assert decrypted == original_data
print("File encryption/decryption using unwrapped key also successful.")