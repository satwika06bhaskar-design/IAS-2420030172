import socket

HOST = "127.0.0.1"
PORT = 5002

# Public Diffie-Hellman values
P = 23
G = 5

# Server private key
PRIVATE_KEY = 6


def calculate_public_key():
    return pow(G, PRIVATE_KEY, P)


def calculate_shared_key(client_public_key):
    return pow(client_public_key, PRIVATE_KEY, P)


print("=" * 70)
print("                 DIFFIE-HELLMAN SERVER")
print("=" * 70)

print()
print("Algorithm : Diffie-Hellman Key Exchange")
print("Public P  :", P)
print("Public G  :", G)
print("Private Key:", PRIVATE_KEY)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

print()
print("Waiting for client...")

conn, address = server.accept()

print("Connected to:", address)

# --------------------------------------------------
# Diffie-Hellman Key Exchange
# --------------------------------------------------

server_public_key = calculate_public_key()

# Receive client public key
client_public_key = int(conn.recv(1024).decode())

print()
print("Client Public Key :", client_public_key)

# Send server public key
conn.send(str(server_public_key).encode())

print("Server Public Key :", server_public_key)

# Calculate shared secret
shared_key = calculate_shared_key(client_public_key)

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

    # Receive client message
    data = conn.recv(4096)

    if not data:
        break

    message = data.decode()

    if message.lower() == "exit":
        print()
        print("Client ended communication.")
        break

    print()
    print("CLIENT -> SERVER")
    print("Message :", message)

    # Server reply
    reply = input("Enter server message: ")

    if reply.lower() == "exit":
        conn.send(b"exit")
        break

    conn.send(reply.encode())


conn.close()
server.close()

print()
print("Server stopped.")
