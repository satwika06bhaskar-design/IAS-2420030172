import socket

HOST = "127.0.0.1"
PORT = 5000

# Hill Cipher Key Matrix
KEY = [[3, 3],
       [2, 5]]


def hill_encrypt(text):
    text = text.upper().replace(" ", "")

    if len(text) % 2 != 0:
        text += "X"

    ciphertext = ""

    for i in range(0, len(text), 2):
        x1 = ord(text[i]) - ord('A')
        x2 = ord(text[i + 1]) - ord('A')

        y1 = (KEY[0][0] * x1 + KEY[0][1] * x2) % 26
        y2 = (KEY[1][0] * x1 + KEY[1][1] * x2) % 26

        ciphertext += chr(y1 + ord('A'))
        ciphertext += chr(y2 + ord('A'))

    return ciphertext


def hill_decrypt(ciphertext):
    # Inverse of [[3,3],[2,5]] modulo 26
    # Inverse matrix = [[15,17],[20,9]]
    INV_KEY = [[15, 17],
               [20, 9]]

    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        x1 = ord(ciphertext[i]) - ord('A')
        x2 = ord(ciphertext[i + 1]) - ord('A')

        y1 = (INV_KEY[0][0] * x1 + INV_KEY[0][1] * x2) % 26
        y2 = (INV_KEY[1][0] * x1 + INV_KEY[1][1] * x2) % 26

        plaintext += chr(y1 + ord('A'))
        plaintext += chr(y2 + ord('A'))

    return plaintext


print("=" * 70)
print("                    HILL CIPHER SERVER")
print("=" * 70)

print("\nAlgorithm : Hill Cipher")
print("Key       : [[3, 3], [2, 5]]")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("\nWaiting for client...")

conn, address = server.accept()

print("Connected to:", address)
print("\nTwo-way communication started.")
print("Type 'exit' to stop.\n")


while True:

    # ==============================
    # RECEIVE FROM CLIENT
    # ==============================

    encrypted_data = conn.recv(4096).decode()

    if not encrypted_data:
        break

    if encrypted_data.lower() == "exit":
        print("\nClient ended the communication.")
        break

    print("=" * 70)
    print("CLIENT -> SERVER")
    print("=" * 70)

    print("\nCiphertext received :", encrypted_data)

    decrypted_message = hill_decrypt(encrypted_data)

    print("Decrypted message   :", decrypted_message)

    # ==============================
    # SERVER REPLY
    # ==============================

    message = input("\nEnter server message: ")

    if message.lower() == "exit":
        conn.send("exit".encode())
        break

    encrypted_reply = hill_encrypt(message)

    print("Encrypted message   :", encrypted_reply)

    conn.send(encrypted_reply.encode())

    print("\nWaiting for next message...\n")


conn.close()
server.close()

print("\nServer stopped.")