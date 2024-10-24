import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# AES key for decryption (must match the server's key)
key = b'This is a key123'  # Ensure the key length is correct


def decrypt_data(encrypted_data, key):
    """
    Decrypts data using AES in CBC mode with padding.

    Parameters:
        encrypted_data (bytes): The IV prepended to the ciphertext.
        key (bytes): The AES decryption key.

    Returns:
        bytes: The decrypted plaintext data.
    """
    # TODO: Extract the IV from the beginning of encrypted_data

    # TODO: Create a new AES cipher in CBC mode using the key and extracted IV

    # TODO: Decrypt the data (excluding the IV) and unpad to retrieve the original message

    return None  # Replace with actual decrypted data after completing decryption


def request_file(filename):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 9999))

    try:
        # Send the filename to the server
        client_socket.send(filename.encode())
        print(f"Requested file: {filename}")

        # Receive the encrypted data from the server
        encrypted_data = b''
        while True:
            part = client_socket.recv(1024)
            if not part:
                break
            encrypted_data += part

        # TODO: Decrypt the received data

        # TODO: Save the decrypted data to a file
        print(f"File '{filename}' received and saved.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")


filename = input("Enter the filename to request: ")
request_file(filename)
