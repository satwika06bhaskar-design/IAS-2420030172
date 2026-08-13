import socket
import struct

HOST = "127.0.0.1"
PORT = 5001

# =========================
# SDES TABLES
# =========================

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


# =========================
# SDES FUNCTIONS
# =========================

def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def xor(a, b):
    return ''.join(
        '0' if x == y else '1'
        for x, y in zip(a, b)
    )


def generate_keys(key):

    p10 = permute(key, P10)

    left = left_shift(p10[:5], 1)
    right = left_shift(p10[5:], 1)

    k1 = permute(left + right, P8)

    left = left_shift(left, 2)
    right = left_shift(right, 2)

    k2 = permute(left + right, P8)

    return k1, k2


def sbox(bits, box):

    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)

    return format(box[row][col], "02b")


def fk(bits, key):

    left = bits[:4]
    right = bits[4:]

    expanded = permute(right, EP)

    xored = xor(expanded, key)

    output = (
        sbox(xored[:4], S0) +
        sbox(xored[4:], S1)
    )

    output = permute(output, P4)

    return xor(left, output) + right


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


# =========================
# DATA ENCRYPTION
# =========================

def encrypt_data(data, key):

    result = bytearray()

    for byte in data:

        binary = format(byte, "08b")

        encrypted = sdes_encrypt(
            binary,
            key
        )

        result.append(
            int(encrypted, 2)
        )

    return bytes(result)


# =========================
# DATA DECRYPTION
# =========================

def decrypt_data(data, key):

    result = bytearray()

    for byte in data:

        binary = format(byte, "08b")

        decrypted = sdes_decrypt(
            binary,
            key
        )

        result.append(
            int(decrypted, 2)
        )

    return bytes(result)


# =========================
# RECEIVE EXACT DATA
# =========================

def receive_all(conn, size):

    data = bytearray()

    while len(data) < size:

        packet = conn.recv(
            min(65536, size - len(data))
        )

        if not packet:
            raise ConnectionError(
                "Server disconnected."
            )

        data.extend(packet)

    return bytes(data)


# =========================
# SEND EXACT DATA
# =========================

def send_all(conn, data):

    total = 0

    while total < len(data):

        sent = conn.send(
            data[total:]
        )

        if sent == 0:
            raise ConnectionError(
                "Server disconnected."
            )

        total += sent


# =========================
# CLIENT
# =========================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect(
    (HOST, PORT)
)

print("======================================")
print("        SDES FILE TRANSFER CLIENT")
print("======================================")

key = input(
    "Enter 10-bit SDES Key: "
)

if len(key) != 10 or any(
    c not in "01" for c in key
):

    print("Invalid SDES key!")
    client.close()
    exit()

print("\nConnected to server.")


# =========================
# INFINITE LOOP
# =========================

try:

    while True:

        print("\n======================================")
        print("1. Send 1 MB file to Server")
        print("2. Receive 10 KB file from Server")
        print("3. Exit")
        print("======================================")

        choice = input("Enter choice: ").strip()

        # =========================
        # OPTION 1
        # CLIENT → SERVER
        # 1 MB FILE
        # =========================

        if choice == "1":

            try:

                with open(
                    "client_1MB.txt",
                    "rb"
                ) as f:

                    plaintext = f.read()

            except FileNotFoundError:

                print(
                    "\nclient_1MB.txt not found!"
                )

                continue

            if len(plaintext) != 1024 * 1024:

                print(
                    "\nFile must be exactly 1 MB."
                )

                print(
                    "Current size:",
                    len(plaintext),
                    "bytes"
                )

                continue

            print("\nEncrypting 1 MB file...")

            encrypted_data = encrypt_data(
                plaintext,
                key
            )

            # Send command
            send_all(
                client,
                b"1"
            )

            # Send encrypted size
            send_all(
                client,
                struct.pack(
                    "!Q",
                    len(encrypted_data)
                )
            )

            # Send encrypted file
            send_all(
                client,
                encrypted_data
            )

            print("\n1 MB file sent successfully.")

            print(
                "Plaintext size :",
                len(plaintext),
                "bytes"
            )

            print(
                "Ciphertext size:",
                len(encrypted_data),
                "bytes"
            )

            print("\nPlaintext preview:")

            print(
                plaintext[:100]
            )

            print("\nCiphertext preview:")

            print(
                encrypted_data[:100]
            )


        # =========================
        # OPTION 2
        # SERVER → CLIENT
        # 10 KB FILE
        # =========================

        elif choice == "2":

            print("\nRequesting 10 KB file from server...")

            # Send command
            send_all(
                client,
                b"2"
            )

            # Receive encrypted size
            size_data = receive_all(
                client,
                8
            )

            encrypted_size = struct.unpack(
                "!Q",
                size_data
            )[0]

            if encrypted_size == 0:

                print(
                    "Server could not send the file."
                )

                continue

            print(
                "Encrypted file size:",
                encrypted_size,
                "bytes"
            )

            # Receive encrypted file
            encrypted_data = receive_all(
                client,
                encrypted_size
            )

            print(
                "Encrypted file received."
            )

            # Decrypt
            plaintext = decrypt_data(
                encrypted_data,
                key
            )

            # Save decrypted file
            with open(
                "received_10KB.txt",
                "wb"
            ) as f:

                f.write(plaintext)

            print("\n----- CLIENT -----")

            print(
                "Ciphertext size:",
                len(encrypted_data),
                "bytes"
            )

            print(
                "Plaintext size :",
                len(plaintext),
                "bytes"
            )

            print("\nCiphertext preview:")

            print(
                encrypted_data[:100]
            )

            print("\nPlaintext preview:")

            print(
                plaintext[:100]
            )

            print(
                "\nSaved as: received_10KB.txt"
            )


        # =========================
        # OPTION 3
        # EXIT
        # =========================

        elif choice == "3":

            send_all(
                client,
                b"3"
            )

            print("\nClient stopped.")
            break


        else:

            print(
                "\nInvalid choice! Enter only 1, 2, or 3."
            )


except ConnectionResetError:

    print(
        "\nServer connection was closed."
    )

except ConnectionError as e:

    print(
        "\nConnection error:",
        e
    )

finally:

    client.close()