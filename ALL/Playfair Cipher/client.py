import socket
import threading

HOST = "127.0.0.1"
PORT = 5000


# ==============================
# PLAYFAIR MATRIX
# ==============================

def create_matrix(key):

    key = key.upper().replace("J", "I")

    letters = []
    used = set()

    for ch in key:

        if ch.isalpha() and ch not in used:
            letters.append(ch)
            used.add(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":

        if ch not in used:
            letters.append(ch)
            used.add(ch)

    return [letters[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, ch):

    if ch == "J":
        ch = "I"

    for row in range(5):

        for col in range(5):

            if matrix[row][col] == ch:
                return row, col


# ==============================
# PREPARE MESSAGE
# ==============================

def prepare_text(text):

    text = text.upper().replace("J", "I")

    text = "".join(
        ch for ch in text
        if ch.isalpha()
    )

    result = ""
    i = 0

    while i < len(text):

        a = text[i]

        if i + 1 < len(text):

            b = text[i + 1]

            if a == b:

                result += a + "X"
                i += 1

            else:

                result += a + b
                i += 2

        else:

            result += a + "X"
            i += 1

    return result


# ==============================
# ENCRYPTION
# ==============================

def encrypt(text, matrix):

    text = prepare_text(text)

    cipher = ""

    for i in range(0, len(text), 2):

        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        # Same row
        if r1 == r2:

            cipher += matrix[r1][(c1 + 1) % 5]
            cipher += matrix[r2][(c2 + 1) % 5]

        # Same column
        elif c1 == c2:

            cipher += matrix[(r1 + 1) % 5][c1]
            cipher += matrix[(r2 + 1) % 5][c2]

        # Rectangle
        else:

            cipher += matrix[r1][c2]
            cipher += matrix[r2][c1]

    return cipher


# ==============================
# DECRYPTION
# ==============================

def decrypt(cipher, matrix):

    plain = ""

    for i in range(0, len(cipher), 2):

        a = cipher[i]
        b = cipher[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        # Same row
        if r1 == r2:

            plain += matrix[r1][(c1 - 1) % 5]
            plain += matrix[r2][(c2 - 1) % 5]

        # Same column
        elif c1 == c2:

            plain += matrix[(r1 - 1) % 5][c1]
            plain += matrix[(r2 - 1) % 5][c2]

        # Rectangle
        else:

            plain += matrix[r1][c2]
            plain += matrix[r2][c1]

    return plain


# ==============================
# RECEIVE THREAD
# ==============================

def receive_messages(client, matrix):

    while True:

        try:

            cipher = client.recv(4096).decode()

            if not cipher:
                print("\nServer disconnected.")
                break

            if cipher.lower() == "exit":

                print("\nServer ended communication.")
                break

            plaintext = decrypt(cipher, matrix)

            print("\n========== SERVER -> CLIENT ==========")
            print("Ciphertext :", cipher)
            print("Plaintext  :", plaintext)
            print("======================================")

        except:
            break


# ==============================
# CLIENT
# ==============================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect((HOST, PORT))

print("====================================")
print("       PLAYFAIR CIPHER CLIENT")
print("====================================")

key = input("Enter Playfair Keyword: ")

matrix = create_matrix(key)

print("\nPlayfair Matrix:")

for row in matrix:
    print(" ".join(row))

print("\nConnected to server.")
print("Type 'exit' to stop.\n")


# Receive thread
thread = threading.Thread(
    target=receive_messages,
    args=(client, matrix),
    daemon=True
)

thread.start()


# ==============================
# SEND LOOP
# ==============================

while True:

    message = input("Client: ")

    if message.lower() == "exit":

        client.send("exit".encode())
        break

    cipher = encrypt(message, matrix)

    print("Encrypted Sent :", cipher)

    client.send(cipher.encode())


client.close()

print("\nClient stopped.")