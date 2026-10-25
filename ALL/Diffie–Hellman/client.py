import socket

HOST = "127.0.0.1"
PORT = 5002

# Public Diffie-Hellman values
P = 23
G = 5

# Client private key
PRIVATE_KEY = 15


def calculate_public_key():
    return pow(G, PRIVATE_KEY, P)


def calculate_shared_key(server_public_key):
    return pow(server_public_key, PRIVATE_KEY, P)


print("=" * 70)
print("                 DIFFIE-HELLMAN CLIENT")
print("=" * 70)

print()
print("Algorithm : Diffie-Hellman Key Exchange")
print("Public P  :", P)
print("Public G  :", G)
print("Private Key:", PRIVATE_KEY)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print()
print("Connected to server.")

# --------------------------------------------------
# Diffie-Hellman Key Exchange
# --------------------------------------------------

client_public_key = calculate_public_key()

# Send client public key
client.send(str(client_public_key).encode())

print()
print("Client Public Key :", client_public_key)

# Receive server public key
server_public_key = int(client.recv(1024).decode())

print("Server Public Key :", server_public_key)

# Calculate shared secret
shared_key = calculate_shared_key(server_public_key)

print()
print("Shared Secret Key  :", shared_key)

print()
print("=" * 70)
print("Diffie-Hellman key exchange completed.")
print("Two-way communication started.")
print("Type 'exit' to stop.")
print("=" * 70)


# --------------------------------------------------
# Continuous two-way communication
# --------------------------------------------------

while True:

    # Client message
    message = input("\nEnter client message: ")

    if message.lower() == "exit":
        client.send(b"exit")
        break

    client.send(message.encode())

    # Receive server reply
    data = client.recv(4096)

    if not data:
        break

    reply = data.decode()

    if reply.lower() == "exit":
        print()
        print("Server ended communication.")
        break

    print()
    print("SERVER -> CLIENT")
    print("Message :", reply)


client.close()

print()
print("Client stopped.")
