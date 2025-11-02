import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
import os

# derive_aes_key function is identical to the baseline
def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# Function to load the server's long-term private signing key
def load_server_identity():
    try:
        with open("server_signing_key.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
        return private_key
    except FileNotFoundError:
        print("Error: server_signing_key.pem not found.")
        print("Please run generate_signing_keys.py first.")
        exit(1)

def server():
    # 0. Load the server's long-term identity (signing key)
    server_signing_key = load_server_identity()
    print("Server identity loaded.")

    # 1. Generate server's *ephemeral* (session) ECDH keys
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )

    # 2. Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 9999))
    server_socket.listen(1)
    print("FIXED Server is listening on port 9999...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # 3. Receive client's public key
    client_public_key_bytes = conn.recv(1024)
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=client_public_key_bytes
    )

    # 4. !!! NEW STEP: SIGN THE HANDSHAKE !!!
    # We sign our own public key to prove we are the real server
    signature = server_signing_key.sign(
        server_public_key_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    
    # 5. Send our public key AND the signature
    # We create a simple protocol: send length of key, then key, then signature
    key_len_bytes = len(server_public_key_bytes).to_bytes(2, 'big') # 2 bytes for length
    conn.sendall(key_len_bytes + server_public_key_bytes + signature)

    # 6. Derive shared secret
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    aes_key = derive_aes_key(shared_secret)
    print("Handshake complete. AES key derived.")

    # 7. Encrypt and send a message (same as before)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    plaintext = b"Hello from the server!"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    conn.sendall(nonce + ciphertext)

    # 8. Receive and decrypt a message (same as before)
    encrypted_message = conn.recv(1024)
    received_nonce = encrypted_message[:12]
    received_ciphertext = encrypted_message[12:]
    decrypted_message = aesgcm.decrypt(received_nonce, received_ciphertext, None)
    print(f"Decrypted message from client: {decrypted_message.decode()}")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()