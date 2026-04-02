import socket
import sys
import os
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

BUFFER_SIZE = 4096
PORT = 13000
MAX_TITLE_LEN = 100
MAX_CONTENT_LEN = 1000000


def send_raw(sock, data):
    length = len(data).to_bytes(4, byteorder="big")
    sock.sendall(length + data)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def recv_raw(sock):
    length_bytes = recv_exact(sock, 4)
    if length_bytes is None:
        return None
    length = int.from_bytes(length_bytes, byteorder="big")
    if length < 0:
        return None

    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return payload


def pad_bytes(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def unpad_bytes(data):
    if not data:
        raise ValueError("Empty padded data")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-pad_len]


def load_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())


def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext.encode())


def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def aes_encrypt(sym_key, plaintext):
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return cipher.encrypt(pad_bytes(plaintext.encode()))


def aes_decrypt(sym_key, ciphertext):
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return unpad_bytes(cipher.decrypt(ciphertext)).decode()


def compute_mac(sym_key, seq, msg):
    h = SHA256.new()
    h.update(str(seq).encode())
    h.update(b"|")
    h.update(msg.encode())
    h.update(b"|")
    h.update(sym_key)
    return h.hexdigest()


def build_secure_packet(sym_key, seq, msg):
    packet = {
        "seq": seq,
        "msg": msg,
        "mac": compute_mac(sym_key, seq, msg),
    }
    return json.dumps(packet)


def parse_secure_packet(sym_key, expected_seq, packet_text):
    packet = json.loads(packet_text)

    if "seq" not in packet or "msg" not in packet or "mac" not in packet:
        raise ValueError("Malformed secure packet")

    recv_seq = packet["seq"]
    recv_msg = packet["msg"]
    recv_mac = packet["mac"]

    if recv_seq != expected_seq:
        raise ValueError("Sequence mismatch")

    calc_mac = compute_mac(sym_key, recv_seq, recv_msg)
    if recv_mac != calc_mac:
        raise ValueError("MAC verification failed")

    return recv_msg


def send_secure(sock, sym_key, seq, msg):
    wrapped = build_secure_packet(sym_key, seq, msg)
    encrypted = aes_encrypt(sym_key, wrapped)
    send_raw(sock, encrypted)


def recv_secure(sock, sym_key, expected_seq):
    data = recv_raw(sock)
    if data is None:
        return None

    wrapped = aes_decrypt(sym_key, data)
    return parse_secure_packet(sym_key, expected_seq, wrapped)


def get_message_content():
    while True:
        choice = input("Would you like to load content from a file? (Y/N): ").strip().upper()

        if choice == "Y":
            filename = input("Enter the filename: ").strip()

            if not os.path.exists(filename):
                print("File does not exist. Please try again.")
                continue

            try:
                with open(filename, "r") as f:
                    content = f.read()
            except Exception:
                print("Could not read file. Please try again.")
                continue

            if len(content) > MAX_CONTENT_LEN:
                print(f"Content exceeds maximum length of {MAX_CONTENT_LEN} characters. Please try again.")
                continue

            return content

        if choice == "N":
            content = input("Enter the message content: ")

            if len(content) > MAX_CONTENT_LEN:
                print(f"Content exceeds maximum length of {MAX_CONTENT_LEN} characters. Please try again.")
                continue

            return content

        print("Invalid choice. Please enter Y or N.")


def build_email_message(sender_username):
    while True:
        destinations = input("Enter destination (separated by ;): ").strip()
        if destinations == "":
            print("Destination list cannot be empty. Please try again.")
        else:
            break

    while True:
        title = input("Enter title: ").strip()

        if title == "":
            print("Title cannot be empty. Please try again.")
        elif len(title) > MAX_TITLE_LEN:
            print(f"Title exceeds maximum length of {MAX_TITLE_LEN} characters. Please try again.")
        else:
            break

    content = get_message_content()

    email_message = (
        "From: " + sender_username + "\n"
        "To: " + destinations + "\n"
        "Title: " + title + "\n"
        "Content Length: " + str(len(content)) + "\n"
        "Content:\n"
        + content
    )

    return email_message


def do_send_email(sock, sym_key, username, send_seq, recv_seq):
    prompt = recv_secure(sock, sym_key, recv_seq)
    if prompt is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    print("[Enhanced] Verified secure server prompt for sending email.")

    email_message = build_email_message(username)
    send_secure(sock, sym_key, send_seq, email_message)
    send_seq += 1

    print("The message is sent to the server.")

    response = recv_secure(sock, sym_key, recv_seq)
    if response is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    print("[Enhanced] Verified secure server response for email submission.")
    if response.startswith("Rejected:"):
        print(response)

    return True, send_seq, recv_seq


def do_display_inbox(sock, sym_key, send_seq, recv_seq):
    inbox_text = recv_secure(sock, sym_key, recv_seq)
    if inbox_text is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    print("[Enhanced] Verified secure inbox listing.")
    print(inbox_text)

    send_secure(sock, sym_key, send_seq, "OK")
    send_seq += 1

    return True, send_seq, recv_seq


def do_display_email(sock, sym_key, send_seq, recv_seq):
    prompt = recv_secure(sock, sym_key, recv_seq)
    if prompt is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    print("[Enhanced] Verified secure email-index prompt.")

    email_index = input("Enter the email index you wish to view: ").strip()
    send_secure(sock, sym_key, send_seq, email_index)
    send_seq += 1

    email_contents = recv_secure(sock, sym_key, recv_seq)
    if email_contents is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    print("[Enhanced] Verified secure email contents.")
    print(email_contents)
    return True, send_seq, recv_seq


def main():
    server_name = input("Enter server IP or name: ").strip()
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    client_private_key_file = username + "_private.pem"
    server_public_key_file = "server_public.pem"

    if not os.path.exists(client_private_key_file):
        print(f"Client private key file '{client_private_key_file}' not found. Exiting.")
        sys.exit(1)

    if not os.path.exists(server_public_key_file):
        print(f"Server public key file '{server_public_key_file}' not found. Exiting.")
        sys.exit(1)

    try:
        server_public_key = load_public_key(server_public_key_file)
        client_private_key = load_private_key(client_private_key_file)
    except Exception as e:
        print(f"Error loading keys: {e}")
        sys.exit(1)

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_name, PORT))
    except Exception as e:
        print(f"Error connecting to server: {e}")
        sys.exit(1)

    try:
        enc_username = rsa_encrypt(server_public_key, username)
        enc_password = rsa_encrypt(server_public_key, password)

        send_raw(client_socket, enc_username)
        send_raw(client_socket, enc_password)

        first_response = recv_raw(client_socket)
        if first_response is None:
            client_socket.close()
            return

        if first_response == b"Invalid username or password":
            print("Invalid username or password.\nTerminating.")
            client_socket.close()
            return

        sym_key = rsa_decrypt(client_private_key, first_response)

        if len(sym_key) != 32:
            print("Received invalid symmetric key length.")
            client_socket.close()
            return

        print("[Enhanced] Symmetric key received and decrypted successfully.")

        send_seq = 0
        recv_seq = 0

        send_secure(client_socket, sym_key, send_seq, "OK")
        send_seq += 1

        while True:
            menu_text = recv_secure(client_socket, sym_key, recv_seq)
            if menu_text is None:
                break
            recv_seq += 1

            print("[Enhanced] Verified secure menu from server.")
            print(menu_text, end="")

            choice = input().strip()
            while choice not in ["1", "2", "3", "4"]:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")
                choice = input("Choice: ").strip()

            send_secure(client_socket, sym_key, send_seq, choice)
            send_seq += 1

            if choice == "1":
                ok, send_seq, recv_seq = do_send_email(client_socket, sym_key, username, send_seq, recv_seq)
                if not ok:
                    break
            elif choice == "2":
                ok, send_seq, recv_seq = do_display_inbox(client_socket, sym_key, send_seq, recv_seq)
                if not ok:
                    break
            elif choice == "3":
                ok, send_seq, recv_seq = do_display_email(client_socket, sym_key, send_seq, recv_seq)
                if not ok:
                    break
            else:
                print("The connection is terminated with the server.")
                break

    except ValueError as e:
        print("[Enhanced] Security verification failed:", str(e))
    except Exception as e:
        print("Runtime error:", str(e))
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()