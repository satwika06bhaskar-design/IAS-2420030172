import socket
from Crypto.Cipher import ARC4

HOST = "127.0.0.1"
PORT = 5001

KEY = b"SECRETKEY"


def encrypt_message(message):
    cipher = ARC4.new(KEY)
    return cipher.encrypt(message)


def decrypt_message(ciphertext):
    cipher = ARC4.new(KEY)
    return cipher.decrypt(ciphertext)


print("=" * 70)
print("                 RC4 STREAM CIPHER SERVER")
print("=" * 70)

print()
print("Algorithm : RC4")
print("Package   : PyCryptodome")
print("Key       : SECRETKEY")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

print()
print("Waiting for client...")

conn, address = server.accept()

print("Connected to:", address)
print()
print("Two-way communication started.")
print("Type 'exit' to stop.")
print()


while True:

    # Receive encrypted message from client
    ciphertext = conn.recv(4096)

    if not ciphertext:
        break

    # Client wants to stop
    if ciphertext == b"EXIT":
        print()
        print("Client ended the communication.")
        break

    print("=" * 70)
    print("CLIENT -> SERVER")
    print("=" * 70)

    print()
    print("Ciphertext:")
    print(ciphertext.hex())

    # Decrypt received message
    plaintext = decrypt_message(ciphertext)

    print()
    print("Decrypted plaintext:")
    print(plaintext.decode("utf-8"))

    # Server reply
    message = input("\nEnter server message: ")

    if message.lower() == "exit":
        conn.send(b"EXIT")
        break

    plaintext_reply = message.encode("utf-8")

    # Encrypt server message
    encrypted_reply = encrypt_message(plaintext_reply)

    print()
    print("Encrypted ciphertext:")
    print(encrypted_reply.hex())

    # Send encrypted reply
    conn.send(encrypted_reply)

    print()
    print("Waiting for next message...")
    print()


conn.close()
server.close()

print()
print("Server stopped.")