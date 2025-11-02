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

def server():
    # 1. Generate server's private and public keys
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()

    # 2. Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 9999))
    server_socket.listen(1)
    print("Server is listening on port 9999...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # 3. Receive client's public key
    client_public_key_bytes = conn.recv(1024)
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=client_public_key_bytes
    )

    # 4. Send server's public key to the client
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    conn.sendall(server_public_key_bytes)

    # 5. Derive shared secret
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    aes_key = derive_aes_key(shared_secret)
    print("Handshake complete. AES key derived.")

    # 6. Encrypt and send a message
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    plaintext = b"Hello from the server!"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    conn.sendall(nonce + ciphertext)

    # 7. Receive and decrypt a message
    encrypted_message = conn.recv(1024)
    received_nonce = encrypted_message[:12]
    received_ciphertext = encrypted_message[12:]
    decrypted_message = aesgcm.decrypt(received_nonce, received_ciphertext, None)
    print(f"Decrypted message from client: {decrypted_message.decode()}")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()