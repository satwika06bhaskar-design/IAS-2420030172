import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"
PORT = 5003

print("=" * 70)
print("                         RSA SERVER")
print("=" * 70)

print()
print("Algorithm : RSA")
print("Package   : PyCryptodome")

# Generate server RSA key pair
server_key = RSA.generate(2048)

server_private_key = server_key
server_public_key = server_key.publickey()

print()
print("RSA key pair generated.")
print("Waiting for client...")

# Create server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

conn, address = server.accept()

print("Connected to:", address)

# --------------------------------------------------
# Exchange public keys
# --------------------------------------------------

# Send server public key
server_public_key_data = server_public_key.export_key()

conn.sendall(len(server_public_key_data).to_bytes(4, "big"))
conn.sendall(server_public_key_data)

# Receive client public key
key_length = int.from_bytes(conn.recv(4), "big")

client_public_key_data = b""

while len(client_public_key_data) < key_length:
    data = conn.recv(key_length - len(client_public_key_data))

    if not data:
        break

    client_public_key_data += data

client_public_key = RSA.import_key(client_public_key_data)

print()
print("Client public key received.")
print("Server public key sent.")

print()
print("=" * 70)
print("RSA key exchange completed.")
print("Two-way encrypted communication started.")
print("Type 'exit' to stop.")
print("=" * 70)


# --------------------------------------------------
# Continuous two-way communication
# --------------------------------------------------

while True:

    # Receive encrypted message from client
    length_data = conn.recv(4)

    if not length_data:
        break

    message_length = int.from_bytes(length_data, "big")

    encrypted_message = b""

    while len(encrypted_message) < message_length:
        data = conn.recv(message_length - len(encrypted_message))

        if not data:
            break

        encrypted_message += data

    # Decrypt using server private key
    cipher = PKCS1_OAEP.new(server_private_key)

    plaintext = cipher.decrypt(encrypted_message).decode("utf-8")

    print()
    print("-" * 70)
    print("CLIENT -> SERVER")
    print("-" * 70)

    print()
    print("Encrypted ciphertext:")
    print(encrypted_message.hex())

    print()
    print("Decrypted plaintext:")
    print(plaintext)

    if plaintext.lower() == "exit":
        break

    # Server reply
    reply = input("\nEnter server message: ")

    if reply.lower() == "exit":

        cipher = PKCS1_OAEP.new(client_public_key)
        encrypted_reply = cipher.encrypt(reply.encode())

        conn.sendall(len(encrypted_reply).to_bytes(4, "big"))
        conn.sendall(encrypted_reply)

        break

    # Encrypt using client public key
    cipher = PKCS1_OAEP.new(client_public_key)

    encrypted_reply = cipher.encrypt(reply.encode())

    print()
    print("Encrypted ciphertext:")
    print(encrypted_reply.hex())

    # Send encrypted reply
    conn.sendall(len(encrypted_reply).to_bytes(4, "big"))
    conn.sendall(encrypted_reply)


conn.close()
server.close()

print()
print("Server stopped.")