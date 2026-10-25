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


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

print("=" * 70)
print("                 VIGENERE CIPHER SERVER")
print("=" * 70)
print()
print("Algorithm : Vigenere Cipher")
print("Host      :", HOST)
print("Port      :", PORT)
print("Key       :", KEY)
print()
print("Waiting for client connection...")
print("=" * 70)

conn, address = server.accept()

print("\nClient connected:", address)
print("Two-way communication started.")
print("Type 'exit' to stop.")
print("=" * 70)

while True:

    # Receive encrypted message from client
    data = conn.recv(4096)

    if not data:
        print("\nClient disconnected.")
        break

    encrypted_message = data.decode()

    if encrypted_message.lower() == "exit":
        print("\nClient ended the communication.")
        break

    decrypted_message = vigenere_decrypt(encrypted_message, KEY)

    print("\nCLIENT -> SERVER")
    print("Encrypted :", encrypted_message)
    print("Decrypted :", decrypted_message)

    # Server sends message
    server_message = input("\nEnter server message: ")

    if server_message.lower() == "exit":
        conn.sendall(b"exit")
        break

    encrypted_response = vigenere_encrypt(server_message, KEY)

    print("\nSERVER -> CLIENT")
    print("Plaintext :", server_message)
    print("Encrypted :", encrypted_response)

    conn.sendall(encrypted_response.encode())


conn.close()
server.close()

print("\nServer stopped.")