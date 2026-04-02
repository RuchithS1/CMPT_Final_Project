import socket
import sys
import json
import os
import datetime
import glob

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PORT = 13000

# ===============================
# Socket helpers (framing)
# ===============================

def send_raw(sock, data):
    sock.sendall(len(data).to_bytes(4, "big") + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_raw(sock):
    length_bytes = recv_exact(sock, 4)
    if length_bytes is None:
        return None
    length = int.from_bytes(length_bytes, "big")
    return recv_exact(sock, length)

# ===============================
# AES helpers
# ===============================

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

def aes_encrypt(key, text):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(text.encode()))

def aes_decrypt(key, ciphertext):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext)).decode()

def send_enc(sock, key, text):
    send_raw(sock, aes_encrypt(key, text))

def recv_enc(sock, key):
    data = recv_raw(sock)
    if data is None:
        return None
    return aes_decrypt(key, data)

# ===============================
# RSA helpers
# ===============================

def load_private(name):
    return RSA.import_key(open(name, "rb").read())

def load_public(name):
    return RSA.import_key(open(name, "rb").read())

def rsa_encrypt(pub, data):
    return PKCS1_OAEP.new(pub).encrypt(data)

def rsa_decrypt(priv, data):
    return PKCS1_OAEP.new(priv).decrypt(data)

# ===============================
# Signature
# ===============================

def sign_data(priv, data):
    h = SHA256.new(data)
    return pkcs1_15.new(priv).sign(h)

# ===============================
# Load users
# ===============================

def load_users():
    return json.load(open("user_pass.json"))

# ===============================
# Handle one client
# ===============================

def handle_client(conn, addr, users, server_private):
    print("Client connected from:", addr)

    # ---- AUTH ----
    enc_user = recv_raw(conn)
    enc_pass = recv_raw(conn)

    if enc_user is None or enc_pass is None:
        conn.close()
        return

    try:
        username = rsa_decrypt(server_private, enc_user).decode()
        password = rsa_decrypt(server_private, enc_pass).decode()
    except:
        conn.close()
        return

    if username not in users or users[username] != password:
        send_raw(conn, b"Invalid username or password")
        print("Invalid login:", username)
        conn.close()
        return

    # ---- SUCCESS ----
    print("Connection Accepted and Symmetric Key Generated for client:", username)

    sym_key = get_random_bytes(32)

    client_pub = load_public(f"{username}_public.pem")
    enc_key = rsa_encrypt(client_pub, sym_key)

    signature = sign_data(server_private, sym_key)

    send_raw(conn, enc_key)
    send_raw(conn, signature)

    # wait for OK
    ack = recv_enc(conn, sym_key)
    if ack != "OK":
        conn.close()
        return

    # ---- MENU LOOP ----
    while True:
        menu = """Select the operation:
1) Create and send an email
2) Display the inbox list
3) Display the email contents
4) Terminate the connection
choice: """

        send_enc(conn, sym_key, menu)

        choice = recv_enc(conn, sym_key)
        if choice is None:
            break

        # ---- SEND EMAIL ----
        if choice == "1":
            send_enc(conn, sym_key, "Send the email")

            email = recv_enc(conn, sym_key)
            if email is None:
                break

            lines = email.split("\n")
            sender = lines[0].split(": ")[1]
            receivers = lines[1].split(": ")[1]
            title = lines[2].split(": ")[1]
            content = "\n".join(lines[5:])
            length = len(content)

            print(f"Email from {sender} to {receivers} length {length}")

            timestamp = str(datetime.datetime.now())

            full_email = (
                f"From: {sender}\n"
                f"To: {receivers}\n"
                f"Time and Date: {timestamp}\n"
                f"Title: {title}\n"
                f"Content Length: {length}\n"
                f"Content:\n{content}"
            )

            for r in receivers.split(";"):
                os.makedirs(r, exist_ok=True)
                with open(f"{r}/{sender}_{title}.txt", "w") as f:
                    f.write(full_email)

            send_enc(conn, sym_key, "Email stored successfully.")

        # ---- INBOX ----
        elif choice == "2":
            files = glob.glob(f"{username}/*.txt")

            output = "Index From DateTime Title\n"
            for i, fpath in enumerate(files):
                with open(fpath) as f:
                    lines = f.readlines()
                    sender = lines[0].split(": ")[1].strip()
                    dt = lines[2].split(": ")[1].strip()
                    title = lines[3].split(": ")[1].strip()
                    output += f"{i+1} {sender} {dt} {title}\n"

            send_enc(conn, sym_key, output)
            recv_enc(conn, sym_key)

        # ---- READ EMAIL ----
        elif choice == "3":
            send_enc(conn, sym_key, "the server request email index")

            idx = int(recv_enc(conn, sym_key))
            files = glob.glob(f"{username}/*.txt")

            with open(files[idx-1]) as f:
                send_enc(conn, sym_key, f.read())

        # ---- TERMINATE ----
        else:
            print("Terminating connection with", username)
            break

    conn.close()

# ===============================
# MAIN SERVER
# ===============================

def server():
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', PORT))
        serverSocket.listen(1)
    except socket.error as e:
        print("Socket error:", e)
        sys.exit(1)

    print("The enhanced server is ready to accept connections")

    users = load_users()
    server_private = load_private("server_private.pem")

    while True:
        try:
            connectionSocket, addr = serverSocket.accept()
            handle_client(connectionSocket, addr, users, server_private)

        except KeyboardInterrupt:
            print("Server shutting down.")
            serverSocket.close()
            break

        except Exception as e:
            print("Error:", e)
            connectionSocket.close()

# ===============================
server()
