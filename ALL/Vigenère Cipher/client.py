import socket

HOST = "127.0.0.1"
PORT = 5000

KEY = "SECURITY"


def vigenere_encrypt(text, key):
    result = []
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')

            if char.isupper():
                encrypted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

            result.append(encrypted)
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def vigenere_decrypt(text, key):
    result = []
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')

            if char.isupper():
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

            result.append(decrypted)
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print("=" * 70)
print("                 VIGENERE CIPHER CLIENT")
print("=" * 70)
print()
print("Algorithm : Vigenere Cipher")
print("Host      :", HOST)
print("Port      :", PORT)
print("Key       :", KEY)
print()
print("Connecting to server...")

try:
    client.connect((HOST, PORT))
except ConnectionRefusedError:
    print("\nERROR: Server is not running.")
    print("Start server.py first.")
    client.close()
    exit()

print("Connected to server.")
print("=" * 70)
print("Two-way communication started.")
print("Type 'exit' to stop.")
print("=" * 70)

while True:

    # Client sends message
    message = input("\nEnter client message: ")

    if message.lower() == "exit":
        client.sendall(b"exit")
        break

    encrypted_message = vigenere_encrypt(message, KEY)

    print("\nCLIENT -> SERVER")
    print("Plaintext :", message)
    print("Encrypted :", encrypted_message)

    client.sendall(encrypted_message.encode())

    # Receive server response
    data = client.recv(4096)

    if not data:
        print("\nServer disconnected.")
        break

    encrypted_response = data.decode()

    if encrypted_response.lower() == "exit":
        print("\nServer ended the communication.")
        break

    decrypted_response = vigenere_decrypt(encrypted_response, KEY)

    print("\nSERVER -> CLIENT")
    print("Encrypted :", encrypted_response)
    print("Decrypted :", decrypted_response)


client.close()

print("\nClient stopped.")