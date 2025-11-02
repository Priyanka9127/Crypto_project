from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate a new private key for signing (ECDSA)
private_key = ec.generate_private_key(ec.SECP256R1())

# Get the public key
public_key = private_key.public_key()

# Serialize and save the private key to a file
with open("server_signing_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
print("Saved server_signing_key.pem")

# Serialize and save the public key to a file
# This is the file you would give to the client (like a CA certificate)
with open("server_public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
print("Saved server_public_key.pem")