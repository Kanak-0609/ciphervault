from key_manager import create_key, get_usable_key, revoke_key
from crypto_utils import encrypt_file, decrypt_file

# Step 1: Create a new key
key_id, fernet_key = create_key()
print("Created key_id:", key_id)

# Step 2: Retrieve it as a usable key (simulates what happens during encryption)
usable_key, error = get_usable_key(key_id)
print("Retrieved key matches original:", usable_key == fernet_key)

# Step 3: Actually use it to encrypt/decrypt something
original = b"Test file contents for CipherVault."
encrypted = encrypt_file(original, usable_key)
decrypted = decrypt_file(encrypted, usable_key)
assert decrypted == original
print("Encrypt/decrypt with retrieved key: success")

# Step 4: Revoke the key
revoked = revoke_key(key_id)
print("Revoke successful:", revoked)

# Step 5: Try to use the revoked key - should now fail with a clear error
usable_key_after_revoke, error = get_usable_key(key_id)
print("Key usable after revoke:", usable_key_after_revoke)
print("Error message:", error)

# Step 6: Try a key_id that doesn't exist at all
fake_key, error = get_usable_key("nonexistent-id-12345")
print("\nFake key result:", fake_key)
print("Error message:", error)