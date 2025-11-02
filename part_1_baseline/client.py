import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
import os

def derive_aes_key(shared_secret):
    # Use HKDF to derive a 256-bit AES key from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def client():
    # 1. Generate client's private and public keys
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_public_key = client_private_key.public_key()

    # 2. Create a TCP/IP socket and connect
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 9999))
    print("Connected to server on port 9999.")

    # 3. Send client's public key to the server
    client_public_key_bytes = client_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    client_socket.sendall(client_public_key_bytes)

    # 4. Receive server's public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=server_public_key_bytes
    )

    # 5. Derive shared secret
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    aes_key = derive_aes_key(shared_secret)
    print("Handshake complete. AES key derived.")

    # 6. Receive and decrypt a message
    encrypted_message = client_socket.recv(1024)
    aesgcm = AESGCM(aes_key)
    received_nonce = encrypted_message[:12]
    received_ciphertext = encrypted_message[12:]
    decrypted_message = aesgcm.decrypt(received_nonce, received_ciphertext, None)
    print(f"Decrypted message from server: {decrypted_message.decode()}")

    # 7. Encrypt and send a message
    nonce = os.urandom(12)
    plaintext = b"Hello from the client!"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    client_socket.sendall(nonce + ciphertext)

    client_socket.close()

if __name__ == "__main__":
    client()