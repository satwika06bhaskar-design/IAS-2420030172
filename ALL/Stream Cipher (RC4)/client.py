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
print("                 RC4 STREAM CIPHER CLIENT")
print("=" * 70)

print()
print("Algorithm : RC4")
print("Package   : PyCryptodome")
print("Key       : SECRETKEY")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print()
print("Connected to server.")
print()
print("Two-way communication started.")
print("Type 'exit' to stop.")
print()


while True:

    # Enter client message
    message = input("Enter client message: ")

    # Stop communication
    if message.lower() == "exit":
        client.send(b"EXIT")
        break

    plaintext = message.encode("utf-8")

    # Encrypt client message
    ciphertext = encrypt_message(plaintext)

    print()
    print("Plaintext:")
    print(message)

    print()
    print("Encrypted ciphertext:")
    print(ciphertext.hex())

    # Send encrypted message
    client.send(ciphertext)

    # Receive server reply
    encrypted_reply = client.recv(4096)

    if not encrypted_reply:
        break

    # Server wants to stop
    if encrypted_reply == b"EXIT":
        print()
        print("Server ended the communication.")
        break

    print()
    print("=" * 70)
    print("SERVER -> CLIENT")
    print("=" * 70)

    print()
    print("Ciphertext received:")
    print(encrypted_reply.hex())

    # Decrypt server reply
    decrypted_reply = decrypt_message(encrypted_reply)

    print()
    print("Decrypted plaintext:")
    print(decrypted_reply.decode("utf-8"))

    print()


client.close()

print()
print("Client stopped.")