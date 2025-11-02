# Project 3: Man-in-the-Middle (MITM) Attack & Defense


## 1. Project Overview

This project demonstrates the "Man-in-the-Middle" (MITM) vulnerability in an unauthenticated key exchange and then implements the cryptographic solution.

The demonstration is in three parts:

* [cite_start]**Part 1: The "Secure" Baseline:** A client and server use Elliptic Curve Diffie-Hellman (ECDH) [cite: 1769-1770, 1832-1833] to establish a shared secret and chat securely with AES-GCM encryption. This *looks* secure.
* **Part 2: The Attack:** We introduce an attacker (`mitm.py`) who intercepts the connection. [cite_start]By performing two separate ECDH handshakes, the attacker can decrypt, read, and re-encrypt all traffic, all while the client and server think they are communicating securely [cite: 1749-1750].
* **Part 3: The Defense:** We fix the vulnerability by implementing **authentication**. The server uses a long-term **Elliptic Curve Digital Signature Algorithm (ECDSA)** key to "sign" its handshake data. The client, holding the server's public key, can now verify the server's identity. [cite_start]This allows the client to detect the imposter and abort the connection [cite: 2650-2651, 2656].

### Core Concepts Used
* **Key Exchange:** Elliptic Curve Diffie-Hellman (ECDH)
* **Encryption:** AES-256 in GCM Mode (AES-GCM)
* **Signatures:** Elliptic Curve Digital Signature Algorithm (ECDSA)
* **Key Derivation:** HKDF (HMAC-based Key Derivation Function)
* **Networking:** Python `socket` and `threading` libraries

---

## 2. How to Run the Demonstration

### Setup

1.  **Clone the repository (or set up the folders).**

2.  **Install dependencies:**
    Open your terminal in the `ECDH-MITM-Project` root folder and run:
    ```bash
    pip install -r requirements.txt
    ```

---

### 演示 Part 1: The "Secure" Baseline

This part shows the "secure" chat application working as intended.

1.  Navigate to the `part_1_baseline` directory:
    ```bash
    cd part_1_baseline
    ```

2.  **Open Terminal 1** and run the server:
    ```bash
    python server.py
    ```
    *Output:* `Server is listening on port 9999...`

3.  **Open Terminal 2** and run the client:
    ```bash
    python client.py
    ```

#### ✅ Expected Result:
Both terminals will connect, print "Handshake complete. AES key derived," and successfully decrypt each other's messages. This appears to be a secure, encrypted chat.

**Server Output:**
```
Server is listening on port 9999...
Connected by ('127.0.0.1', ...)
Handshake complete. AES key derived.
Decrypted message from client: Hello from the client!
```

**Client Output:**
```
Connected to server on port 9999.
Handshake complete. AES key derived.
Decrypted message from server: Hello from the server!
```

---

### 演示 Part 2: The MITM Attack

This part demonstrates the vulnerability. We will use **three terminals**.

1.  Navigate to the `part_2_attack` directory:
    ```bash
    cd part_2_attack
    ```

2.  **Open Terminal 1** and run the **original server**:
    ```bash
    python server.py
    ```
    *Output:* `Server is listening on port 9999...`

3.  **Open Terminal 2** and run the **attacker**:
    ```bash
    python mitm.py
    ```
    *Output:* `MITM Attack Server listening on port 8888...`

4.  **Open Terminal 3** and run the **client** (which is configured to connect to the attacker):
    ```bash
    python client_for_mitm.py
    ```

#### 💥 Expected Result:
The attacker has successfully intercepted the conversation.

* **Terminal 1 (Server)** and **Terminal 3 (Client)** look *exactly the same as in Part 1*. They think they are secure.
* **Terminal 2 (Attacker)** shows the intercepted plaintext messages!

**Attacker's Output (Terminal 2):**
```
MITM Attack Server listening on port 8888...
[MITM] Client connected from ...
[MITM] Connected to real server at localhost:9999
...
[MITM] Handshakes complete. Now relaying and intercepting all traffic.

[MITM] --- INTERCEPTED from SERVER ---
[MITM] Plaintext: Hello from the server!
[MITM] --- END INTERCEPT ---

[MITM] --- INTERCEPTED from CLIENT ---
[MITM] Plaintext: Hello from the client!
[MITM] --- END INTERCEPT ---
```

---

### 演示 Part 3: The Defense

This part shows how digital signatures prevent the attack.

1.  Navigate to the `part_3_defense` directory:
    ```bash
    cd part_3_defense
    ```

2.  **One-Time Setup:** Run the script to generate the server's long-term identity keys.
    ```bash
    python generate_signing_keys.py
    ```
    *Output:* `Saved server_signing_key.pem` and `Saved server_public_key.pem`.

3.  Now, we run the same attack scenario (with 3 terminals).

4.  **Open Terminal 1** and run the **fixed server**:
    ```bash
    python server_fixed.py
    ```
    *Output:* `FIXED Server is listening on port 9999...`

5.  **Open Terminal 2** and run the **attacker**:
    ```bash
    python mitm.py
    ```
    *Output:* `MITM Attack Server listening on port 8888...`

6.  **Open Terminal 3** and run the **fixed client**:
    ```bash
    python client_fixed.py
    ```

#### 🛡️ Expected Result:
The attack is **foiled**. The client immediately detects the imposter and aborts the connection.

**Client's Output (Terminal 3):**
```
Trusted server CA loaded.
Connected to port 8888... (Testing for MITM)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! MITM ATTACK DETECTED !!!
!!! Server signature is INVALID.     !!!
!!! Aborting connection.             !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

This happens because the `mitm.py` attacker cannot produce a valid digital signature that the client trusts, proving our defense works.