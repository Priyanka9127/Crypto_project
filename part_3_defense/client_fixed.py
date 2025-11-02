import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.exceptions import InvalidSignature
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

# Function to load the server's trusted public signing key
def load_server_ca():
    try:
        with open("server_public_key.pem", "rb") as f:
            public_key = load_pem_public_key(f.read())
        return public_key
    except FileNotFoundError:
        print("Error: server_public_key.pem not found.")
        print("Please run generate_signing_keys.py first.")
        exit(1)

def client():
    # 0. Load the server's trusted public key (CA)
    server_public_ca = load_server_ca()
    print("Trusted server CA loaded.")

    # 1. Generate client's private and public keys
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = client_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )

    # 2. Connect to the attacker/server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # We will still connect to the MITM to prove our defense works
        client_socket.connect(('localhost', 8888))
        print("Connected to port 8888... (Testing for MITM)")
    except ConnectionRefusedError:
        print("Connection failed. Is the MITM or Server running?")
        return

    # 3. Send client's public key
    client_socket.sendall(client_public_key_bytes)

    # 4. Receive the server's public key AND signature
    header = client_socket.recv(2) # Read the 2-byte length header
    key_len = int.from_bytes(header, 'big')
    
    # Read the exact length of the key
    server_public_key_bytes = client_socket.recv(key_len)
    
    # The rest of the message is the signature
    signature = client_socket.recv(1024) 

    # 5. !!! NEW STEP: VERIFY THE SIGNATURE !!!
    try:
        server_public_ca.verify(
            signature,
            server_public_key_bytes, # The data that was signed
            ec.ECDSA(hashes.SHA256())
        )
        print("Server signature VERIFIED. Connection is authentic.")
    except InvalidSignature:
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! MITM ATTACK DETECTED !!!")
        print("!!! Server signature is INVALID.     !!!")
        print("!!! Aborting connection.             !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
        client_socket.close()
        return # Abort
    except Exception as e:
        print(f"An error occurred during verification (likely from MITM): {e}")
        client_socket.close()
        return # Abort

    # If verification passed, we can safely proceed
    server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=server_public_key_bytes
    )

    # 6. Derive shared secret
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    aes_key = derive_aes_key(shared_secret)
    print("Handshake complete. AES key derived.")

    # 7. Receive and decrypt a message
    encrypted_message = client_socket.recv(1024)
    aesgcm = AESGCM(aes_key)
    received_nonce = encrypted_message[:12]
    received_ciphertext = encrypted_message[12:]
    decrypted_message = aesgcm.decrypt(received_nonce, received_ciphertext, None)
    print(f"Decrypted message from server: {decrypted_message.decode()}")

    # 8. Encrypt and send a message
    nonce = os.urandom(12)
    plaintext = b"Hello from the client!"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    client_socket.sendall(nonce + ciphertext)

    client_socket.close()

if __name__ == "__main__":
    client()