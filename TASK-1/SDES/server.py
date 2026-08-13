import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def xor(a, b):
    return ''.join('0' if x == y else '1'
                   for x, y in zip(a, b))


def generate_keys(key):

    p10 = permute(key, P10)

    left = p10[:5]
    right = p10[5:]

    left = left_shift(left, 1)
    right = left_shift(right, 1)

    k1 = permute(left + right, P8)

    left = left_shift(left, 2)
    right = left_shift(right, 2)

    k2 = permute(left + right, P8)

    return k1, k2


def sbox(bits, box):

    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)

    return format(box[row][col], '02b')


def fk(bits, key):

    left = bits[:4]
    right = bits[4:]

    expanded = permute(right, EP)

    xored = xor(expanded, key)

    left_part = sbox(xored[:4], S0)
    right_part = sbox(xored[4:], S1)

    p4 = permute(left_part + right_part, P4)

    return xor(left, p4) + right


def sdes_encrypt(bits, key):

    k1, k2 = generate_keys(key)

    temp = permute(bits, IP)

    temp = fk(temp, k1)

    temp = temp[4:] + temp[:4]

    temp = fk(temp, k2)

    return permute(temp, IP_INV)


def sdes_decrypt(bits, key):

    k1, k2 = generate_keys(key)

    temp = permute(bits, IP)

    temp = fk(temp, k2)

    temp = temp[4:] + temp[:4]

    temp = fk(temp, k1)

    return permute(temp, IP_INV)


def encrypt_message(message, key):

    cipher = ""

    for ch in message:

        binary = format(ord(ch), '08b')

        cipher += sdes_encrypt(binary, key)

    return cipher


def decrypt_message(cipher, key):

    plaintext = ""

    for i in range(0, len(cipher), 8):

        block = cipher[i:i + 8]

        binary = sdes_decrypt(block, key)

        plaintext += chr(int(binary, 2))

    return plaintext


def receive_messages(conn, key):

    while True:

        try:

            cipher = conn.recv(65536).decode()

            if not cipher:
                print("\nClient disconnected.")
                break

            if cipher == "EXIT":
                print("\nClient ended communication.")
                break

            plaintext = decrypt_message(cipher, key)

            print("\n========== CLIENT -> SERVER ==========")
            print("Ciphertext :", cipher)
            print("Plaintext  :", plaintext)
            print("======================================")

        except Exception as e:

            print("\nConnection error:", e)
            break


# ==============================
# SERVER
# ==============================

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, PORT))
server.listen(1)

print("======================================")
print("          SDES CIPHER SERVER")
print("======================================")
print("Waiting for client...")

conn, addr = server.accept()

print("Connected to:", addr)

key = input("Enter 10-bit SDES Key: ")

if len(key) != 10 or any(ch not in "01" for ch in key):

    print("Invalid key!")
    print("Key must contain exactly 10 bits.")

    conn.close()
    server.close()
    exit()

print("\nSDES Server Ready.")
print("Type messages continuously.")
print("Type 'exit' to stop.\n")


thread = threading.Thread(
    target=receive_messages,
    args=(conn, key),
    daemon=True
)

thread.start()


while True:

    message = input("Server: ")

    if message.lower() == "exit":

        conn.send("EXIT".encode())
        break

    cipher = encrypt_message(message, key)

    print("Encrypted Sent :", cipher)

    conn.send(cipher.encode())


conn.close()
server.close()

print("\nServer stopped.")