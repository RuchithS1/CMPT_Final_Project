import socket
import sys
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

BUFFER_SIZE = 4096
PORT = 13000
MAX_TITLE_LEN = 100
MAX_CONTENT_LEN = 1000000

#Adding a framed socket I/O

def send_raw(sock, data):
    length = len(data).to_bytes(4, byteorder="big")
    sock.sendall(length + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise None
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

#Adding helpers for the AES ECB encryption

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

#Adding a helper to load the RSA public key / AES helepers

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

def send_encrypted(sock, sym_key, text):
    send_raw(sock, aes_encrypt(sym_key, text))

def recv_encrypted(sock, sym_key):
    data = recv_raw(sock)
    if data is None:
        return None
    return aes_decrypt(sym_key, data)

#Adding email validation helper

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
        
        elif choice == "N":
            content = input("Enter the message content: ")

            if len(content) > MAX_CONTENT_LEN:
                print(f"Content exceeds maximum length of {MAX_CONTENT_LEN} characters. Please try again.")
                continue

            return content
        
        else:
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

#Adding client operations

def do_send_email(sock, sym_key, username):
    prompt = recv_encrypted(sock, sym_key)
    if prompt is None:
        return False

    # send the email message
    email_message = build_email_message(username)    
    send_encrypted(sock, sym_key, email_message)

    print("The message is sent to the server.")

    # Adding the server response confirmation/rejection message.
    response = recv_encrypted(sock, sym_key)
    if response is None:
        return False

    if response.startswith("Rejected:"):
        print(response)

    return True

def do_display_inbox(sock, sym_key):
    inbox_text = recv_encrypted(sock, sym_key)
    if inbox_text is None:
        return False
    
    print(inbox_text)
    send_encrypted(sock, sym_key, "OK")
    return True
    
def do_display_email(sock, sym_key):
    prompt = recv_encrypted(sock, sym_key)
    if prompt is None:
        return False
    
    # putting the server request email index
    email_index = input("Enter the email index you wish to view: ").strip()
    send_encrypted(sock, sym_key, email_index)

    email_contents = recv_encrypted(sock, sym_key)
    if email_contents is None:
        return False
    
    print(email_contents)
    return True

#Adding the main client loop

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
        #I am sending the username and password as two separate RSA encrypted messages.
        enc_username = rsa_encrypt(server_public_key, username)
        enc_password = rsa_encrypt(server_public_key, password)

        send_raw(client_socket, enc_username)
        send_raw(client_socket, enc_password)

        # receive the encrypted symmetric key from the server and decrypt it using the client's private RSA key
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
        
        send_encrypted(client_socket, sym_key, "OK")

        while True:
            menu_text = recv_encrypted(client_socket, sym_key)
            if menu_text is None:
                break

            print(menu_text, end="")

            choice = input().strip()
            while choice not in ["1", "2", "3", "4"]:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")
                choice = input("Choice: ").strip()

            send_encrypted(client_socket, sym_key, choice)

            if choice == "1":
                if not do_send_email(client_socket, sym_key, username):
                    break
            elif choice == "2":
                if not do_display_inbox(client_socket, sym_key):
                    break
            elif choice == "3":
                if not do_display_email(client_socket, sym_key):
                    break
            else:
                print("The connection is terminated with the server.")
                break

    except Exception as e:
        print("Runtime error:", str(e))
    finally:
        try:
            client_socket.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()    