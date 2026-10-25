import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"
PORT = 5003

print("=" * 70)
print("                         RSA CLIENT")
print("=" * 70)

print()
print("Algorithm : RSA")
print("Package   : PyCryptodome")

# Generate client RSA key pair
client_key = RSA.generate(2048)

client_private_key = client_key
client_public_key = client_key.publickey()

print()
print("RSA key pair generated.")

# Connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print("Connected to server.")

# --------------------------------------------------
# Exchange public keys
# --------------------------------------------------

# Receive server public key
key_length = int.from_bytes(client.recv(4), "big")

server_public_key_data = b""

while len(server_public_key_data) < key_length:
    data = client.recv(key_length - len(server_public_key_data))

    if not data:
        break

    server_public_key_data += data

server_public_key = RSA.import_key(server_public_key_data)

# Send client public key
client_public_key_data = client_public_key.export_key()

client.sendall(len(client_public_key_data).to_bytes(4, "big"))
client.sendall(client_public_key_data)

print()
print("Server public key received.")
print("Client public key sent.")

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

    message = input("\nEnter client message: ")

    # Encrypt using server public key
    cipher = PKCS1_OAEP.new(server_public_key)

    encrypted_message = cipher.encrypt(message.encode())

    print()
    print("Plaintext:")
    print(message)

    print()
    print("Encrypted ciphertext:")
    print(encrypted_message.hex())

    # Send encrypted message
    client.sendall(len(encrypted_message).to_bytes(4, "big"))
    client.sendall(encrypted_message)

    if message.lower() == "exit":
        break

    # Receive encrypted server reply
    length_data = client.recv(4)

    if not length_data:
        break

    reply_length = int.from_bytes(length_data, "big")

    encrypted_reply = b""

    while len(encrypted_reply) < reply_length:
        data = client.recv(reply_length - len(encrypted_reply))

        if not data:
            break

        encrypted_reply += data

    # Decrypt using client private key
    cipher = PKCS1_OAEP.new(client_private_key)

    reply = cipher.decrypt(encrypted_reply).decode("utf-8")

    print()
    print("-" * 70)
    print("SERVER -> CLIENT")
    print("-" * 70)

    print()
    print("Ciphertext received:")
    print(encrypted_reply.hex())

    print()
    print("Decrypted plaintext:")
    print(reply)

    if reply.lower() == "exit":
        break


client.close()

print()
print("Client stopped.")