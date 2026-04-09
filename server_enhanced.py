import json
import socket
import os
import glob
import datetime
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


PORT = 13000
BACKLOG = 5
MAX_TITLE_LEN = 100
MAX_CONTENT_LEN = 1000000

MENU = """Select the operation:
1) Create and send an email
2) Display the inbox list
3) Display the email contents
4) Terminate the connection 
choice: """

# Basic framed socket I/O
# We use a 4-byte big-endian length prefix for every message
def send_raw(sock, data):
    length = len(data).to_bytes(4, byteorder="big")
    sock.sendall(length + data)


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
    length = int.from_bytes(length_bytes, byteorder="big")
    if length < 0:
        return None
    return recv_exact(sock, length)


# Padding helpers for AES ECB
#########################################
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


def load_rsa_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

# RSA / AES helpers
# ============================================================
def load_rsa_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())


def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def rsa_encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


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



# File / parsing helpers
# ============================================================

def load_users():
    with open("user_pass.json", "r") as f:
        return json.load(f)


def ensure_user_dirs(users):
    for username in users:
        if not os.path.isdir(username):
            os.makedirs(username)


def sanitize_title_for_filename(title):
    cleaned = ""
    for ch in title:
        if ch in '/\\:*?"<>|':
            cleaned += "_"
        else:
            cleaned += ch
    return cleaned.strip()


def parse_email(email_text):
    lines = email_text.split("\n")

    if len(lines) < 5:
        raise ValueError("Malformed email")

    if not lines[0].startswith("From: "):
        raise ValueError("Missing From field")
    if not lines[1].startswith("To: "):
        raise ValueError("Missing To field")
    if not lines[2].startswith("Title: "):
        raise ValueError("Missing Title field")
    if not lines[3].startswith("Content Length: "):
        raise ValueError("Missing Content Length field")
    if lines[4] != "Content:":
        raise ValueError("Missing Content field")

    sender = lines[0][6:].strip()
    destinations = lines[1][4:].strip()
    title = lines[2][7:].strip()
    content_length_str = lines[3][16:].strip()
    content = "\n".join(lines[5:])

    if len(title) > MAX_TITLE_LEN:
        raise ValueError("Title too long")

    try:
        declared_length = int(content_length_str)
    except Exception:
        raise ValueError("Invalid content length")

    if declared_length != len(content):
        raise ValueError("Content length mismatch")

    if len(content) > MAX_CONTENT_LEN:
        raise ValueError("Content too long")

    recipients = [x.strip() for x in destinations.split(";") if x.strip()]
    if len(recipients) == 0:
        raise ValueError("No recipients")

    return {
        "from": sender,
        "to": recipients,
        "to_str": ";".join(recipients),
        "title": title,
        "content_length": declared_length,
        "content": content,
    }


def build_saved_email(email_info, received_dt):
    return (
        "From: " + email_info["from"] + "\n"
        "To: " + email_info["to_str"] + "\n"
        "Time and Date: " + str(received_dt) + "\n"
        "Title: " + email_info["title"] + "\n"
        "Content Length: " + str(email_info["content_length"]) + "\n"
        "Content:\n"
        + email_info["content"]
    )


def save_email_for_recipient(recipient, email_info, received_dt):
    title_for_file = sanitize_title_for_filename(email_info["title"])
    filename = email_info["from"] + "_" + title_for_file + ".txt"
    path = os.path.join(recipient, filename)

    email_text = build_saved_email(email_info, received_dt)
    with open(path, "w") as f:
        f.write(email_text)


def parse_saved_email_metadata(filepath):
    sender = ""
    dt_str = ""
    title = ""

    with open(filepath, "r") as f:
        lines = f.read().split("\n")

    for line in lines:
        if line.startswith("From: "):
            sender = line[6:].strip()
        elif line.startswith("Time and Date: "):
            dt_str = line[15:].strip()
        elif line.startswith("Title: "):
            title = line[7:].strip()

    try:
        dt_obj = datetime.datetime.fromisoformat(dt_str)
    except Exception:
        dt_obj = datetime.datetime.min

    return sender, dt_str, title, dt_obj


def get_inbox_list(username):
    folder = username
    if not os.path.isdir(folder):
        return []

    files = glob.glob(os.path.join(folder, "*.txt"))
    info = []

    for path in files:
        sender, dt_str, title, dt_obj = parse_saved_email_metadata(path)
        info.append(
            {
                "path": path,
                "sender": sender,
                "dt_str": dt_str,
                "dt_obj": dt_obj,
                "title": title,
            }
        )

    info.sort(key=lambda x: x["dt_obj"])
    return info


def build_inbox_listing(username):
    inbox = get_inbox_list(username)
    if len(inbox) == 0:
        return "Inbox is empty."

    lines = ["Index From DateTime Title"]
    idx = 1
    for item in inbox:
        lines.append(
            str(idx) + " " + item["sender"] + " " + item["dt_str"] + " " + item["title"]
        )
        idx += 1
    return "\n".join(lines)


def authenticate_client(conn, server_private_key, users):
    enc_username = recv_raw(conn)
    if enc_username is None:
        return None, None

    enc_password = recv_raw(conn)
    if enc_password is None:
        return None, None

    try:
        username = rsa_decrypt(server_private_key, enc_username).decode().strip()
        password = rsa_decrypt(server_private_key, enc_password).decode().strip()
    except Exception:
        return None, None

    if username in users and users[username] == password:
        return username, password

    return username, None


def send_sym_key_to_client(conn, username, sym_key):
    client_pub_filename = username + "_public.pem"
    client_public_key = load_rsa_public_key(client_pub_filename)
    encrypted_key = rsa_encrypt(client_public_key, sym_key)
    send_raw(conn, encrypted_key)

#handling email send from client to server
def handle_send_email(conn, username, sym_key, users, send_seq, recv_seq):
    send_secure(conn, sym_key, send_seq, "Send the email")
    send_seq += 1

    email_text = recv_secure(conn, sym_key, recv_seq)
    if email_text is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    try:
        email_info = parse_email(email_text)

        if email_info["from"] != username:
            send_secure(conn, sym_key, send_seq, "Rejected: sender mismatch.")
            send_seq += 1
            return True, send_seq, recv_seq

        for recipient in email_info["to"]:
            if recipient not in users:
                send_secure(conn, sym_key, send_seq, "Rejected: unknown recipient " + recipient)
                send_seq += 1
                return True, send_seq, recv_seq

        received_dt = datetime.datetime.now()
        print(
            "An email from "
            + email_info["from"]
            + " is sent to "
            + email_info["to_str"]
            + " has a content length of "
            + str(email_info["content_length"])
            + " ."
        )

        for recipient in email_info["to"]:
            save_email_for_recipient(recipient, email_info, received_dt)

        send_secure(conn, sym_key, send_seq, "Email stored successfully.")
        send_seq += 1
        return True, send_seq, recv_seq

    except Exception as e:
        send_secure(conn, sym_key, send_seq, "Rejected: " + str(e))
        send_seq += 1
        return True, send_seq, recv_seq

# shows list ofemails for users
def handle_display_inbox(conn, username, sym_key, send_seq, recv_seq):
    inbox_text = build_inbox_listing(username)
    send_secure(conn, sym_key, send_seq, inbox_text)
    send_seq += 1

    ack = recv_secure(conn, sym_key, recv_seq)
    if ack is None:
        return False, send_seq, recv_seq
    recv_seq += 1
    return True, send_seq, recv_seq

# Display one selected email
def handle_display_email(conn, username, sym_key, send_seq, recv_seq):
    send_secure(conn, sym_key, send_seq, "the server request email index")
    send_seq += 1

    enc_index = recv_secure(conn, sym_key, recv_seq)
    if enc_index is None:
        return False, send_seq, recv_seq
    recv_seq += 1

    try:
        index = int(enc_index.strip())
    except Exception:
        send_secure(conn, sym_key, send_seq, "Invalid email index.")
        send_seq += 1
        return True, send_seq, recv_seq

    inbox = get_inbox_list(username)
    if index < 1 or index > len(inbox):
        send_secure(conn, sym_key, send_seq, "Invalid email index.")
        send_seq += 1
        return True, send_seq, recv_seq

    filepath = inbox[index - 1]["path"]
    with open(filepath, "r") as f:
        email_text = f.read()

    send_secure(conn, sym_key, send_seq, email_text)
    send_seq += 1
    return True, send_seq, recv_seq

# controls client session,  Authenticate, generate aes key, initilazi seq numbes and wait for client ack.
def handle_client(conn, addr, server_private_key, users):
    username = None

    try:
        username, valid_password = authenticate_client(conn, server_private_key, users)

        if username is None or valid_password is None:
            send_raw(conn, b"Invalid username or password")
            bad_name = username if username is not None else "UNKNOWN"
            print(
                "The received client information: "
                + bad_name
                + " is invalid (Connection Terminated)."
            )
            conn.close()
            return

        sym_key = get_random_bytes(32)
        send_sym_key_to_client(conn, username, sym_key)

        print("Connection Accepted and Symmetric Key Generated for client: " + username)

        send_seq = 0
        recv_seq = 0

        ack = recv_secure(conn, sym_key, recv_seq)
        if ack is None or ack.strip() != "OK":
            conn.close()
            return
        recv_seq += 1

        while True:
            send_secure(conn, sym_key, send_seq, MENU)
            send_seq += 1

            choice = recv_secure(conn, sym_key, recv_seq)
            if choice is None:
                break
            recv_seq += 1

            choice = choice.strip()

            if choice == "1":
                ok, send_seq, recv_seq = handle_send_email(
                    conn, username, sym_key, users, send_seq, recv_seq
                )
                if not ok:
                    break
            elif choice == "2":
                ok, send_seq, recv_seq = handle_display_inbox(
                    conn, username, sym_key, send_seq, recv_seq
                )
                if not ok:
                    break
            elif choice == "3":
                ok, send_seq, recv_seq = handle_display_email(
                    conn, username, sym_key, send_seq, recv_seq
                )
                if not ok:
                    break
            else:
                print("Terminating connection with " + username + ".")
                break

    except Exception:
        if username is not None:
            print("Terminating connection with " + username + ".")
    finally:
        conn.close()


def reap_children():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except ChildProcessError:
            break
        except Exception:
            break




def main():
    try:
        users = load_users()
    except Exception as e:
        print("Failed to load user_pass.json:", str(e))
        sys.exit(1)

    ensure_user_dirs(users)

    try:
        server_private_key = load_rsa_private_key("server_private.pem")
    except Exception as e:
        print("Failed to load server_private.pem:", str(e))
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", PORT))
    server_socket.listen(BACKLOG)

    print("The enhanced server is ready to accept connections")

    while True:
        try:
            reap_children()
            conn, addr = server_socket.accept()

            pid = os.fork()

            if pid == 0:
                server_socket.close()
                handle_client(conn, addr, server_private_key, users)
                os._exit(0)
            else:
                conn.close()

        except KeyboardInterrupt:
            server_socket.close()
            break
        except Exception:
            continue


if __name__ == "__main__":
    main()
