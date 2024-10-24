import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os

# AES key for encryption (must be 16, 24, or 32 bytes)
key = b'This is a key123'  # Ensure the key length is correct


def encrypt_data(data, key):
    """
    Encrypts data using AES in CBC mode with padding.

    Parameters:
        data (bytes): The plaintext data to encrypt.
        key (bytes): The AES encryption key.

    Returns:
        bytes: The IV prepended to the ciphertext.
    """
    # TODO: Generate a random initialization vector (IV)

    # TODO: Create a new AES cipher in CBC mode using the key and IV

    # TODO: Pad the data to match AES block size and encrypt

    # Return IV + encrypted data
    return None  # Replace with actual return statement after completing encryption


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 9999))
    server_socket.listen(1)
    print("Server listening on port 9999")

    while True:
        print("Waiting for a connection...")
        client_socket, addr = server_socket.accept()
        print(f"Connected by {addr}")

        try:
            # Receive the filename from the client
            filename = client_socket.recv(1024).decode()
            print(f"Client requested file: {filename}")

            if os.path.isfile(filename):
                with open(filename, "rb") as file:
                    data = file.read()

                    # TODO: Encrypt the file data before sending

                    # TODO: Send encrypted data to the client
                print(f"File '{filename}' sent to the client.")
            else:
                client_socket.send("File not found.".encode())
                print("File not found.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print("Connection closed.")


start_server()
