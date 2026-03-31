from Crypto.PublicKey import RSA
import os

def generate_key_pair(name):
    # Generate RSA key (2048 bits)
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save private key
    with open(f"{name}_private.pem", "wb") as priv_file:
        priv_file.write(private_key)

    # Save public key
    with open(f"{name}_public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print(f"Keys generated for {name}")


def main():
    # Create keys for server
    generate_key_pair("server")

    # Create keys for 5 clients
    for i in range(1, 2):
        generate_key_pair(f"client{i}")

    print("\nAll keys generated successfully.")


if __name__ == "__main__":
    main()