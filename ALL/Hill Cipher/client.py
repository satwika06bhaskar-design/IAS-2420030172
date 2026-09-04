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
print("                    HILL CIPHER CLIENT")
print("=" * 70)

print("\nAlgorithm : Hill Cipher")
print("Key       : [[3, 3], [2, 5]]")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

print("\nConnected to server.")
print("\nTwo-way communication started.")
print("Type 'exit' to stop.\n")


while True:

    # ==============================
    # CLIENT MESSAGE
    # ==============================

    message = input("Enter client message: ")

    if message.lower() == "exit":
        client.send("exit".encode())
        break

    encrypted_message = hill_encrypt(message)

    print("Encrypted message :", encrypted_message)

    client.send(encrypted_message.encode())

    # ==============================
    # RECEIVE SERVER REPLY
    # ==============================

    encrypted_reply = client.recv(4096).decode()

    if not encrypted_reply:
        break

    if encrypted_reply.lower() == "exit":
        print("\nServer ended the communication.")
        break

    print("\n" + "=" * 70)
    print("SERVER -> CLIENT")
    print("=" * 70)

    print("\nCiphertext received :", encrypted_reply)

    decrypted_reply = hill_decrypt(encrypted_reply)

    print("Decrypted message   :", decrypted_reply)

    print("\n")


client.close()

print("\nClient stopped.")