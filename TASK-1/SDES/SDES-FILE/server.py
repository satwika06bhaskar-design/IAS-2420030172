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
                "Client disconnected."
            )

        data.extend(packet)

    return bytes(data)


# =========================
# SEND DATA
# =========================

def send_all(conn, data):

    total = 0

    while total < len(data):

        sent = conn.send(
            data[total:]
        )

        if sent == 0:
            raise ConnectionError(
                "Client disconnected."
            )

        total += sent


# =========================
# SERVER
# =========================

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

server.listen(1)

print("======================================")
print("       SDES FILE TRANSFER SERVER")
print("======================================")
print("Waiting for client...")

conn, addr = server.accept()

print("Connected to:", addr)

key = input(
    "Enter 10-bit SDES Key: "
)

if len(key) != 10 or any(
    c not in "01" for c in key
):

    print("Invalid SDES key!")
    conn.close()
    server.close()
    exit()

print("\nServer ready.")
print("Waiting for client requests...\n")


# =========================
# INFINITE LOOP
# =========================

try:

    while True:

        # Client sends exactly ONE command byte
        command = conn.recv(1)

        if not command:

            print("\nClient disconnected.")
            break

        # =========================
        # COMMAND 1
        # CLIENT → SERVER
        # 1 MB FILE
        # =========================

        if command == b"1":

            print("\n======================================")
            print("Receiving 1 MB file from Client")
            print("======================================")

            size_data = receive_all(
                conn,
                8
            )

            encrypted_size = struct.unpack(
                "!Q",
                size_data
            )[0]

            print(
                "Encrypted file size:",
                encrypted_size,
                "bytes"
            )

            encrypted_data = receive_all(
                conn,
                encrypted_size
            )

            print("Encrypted file received.")

            plaintext = decrypt_data(
                encrypted_data,
                key
            )

            with open(
                "received_1MB.txt",
                "wb"
            ) as f:

                f.write(plaintext)

            print("\n----- SERVER -----")

            print(
                "Ciphertext size :",
                len(encrypted_data),
                "bytes"
            )

            print(
                "Plaintext size  :",
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
                "\nSaved as: received_1MB.txt"
            )


        # =========================
        # COMMAND 2
        # SERVER → CLIENT
        # 10 KB FILE
        # =========================

        elif command == b"2":

            print("\n======================================")
            print("Sending 10 KB file to Client")
            print("======================================")

            try:

                with open(
                    "server_10KB.txt",
                    "rb"
                ) as f:

                    plaintext = f.read()

            except FileNotFoundError:

                print(
                    "server_10KB.txt not found!"
                )

                # Send zero size to client
                send_all(
                    conn,
                    struct.pack("!Q", 0)
                )

                continue

            if len(plaintext) != 10 * 1024:

                print(
                    "Warning: File is not exactly 10 KB."
                )

            encrypted_data = encrypt_data(
                plaintext,
                key
            )

            # First send ciphertext size
            send_all(
                conn,
                struct.pack(
                    "!Q",
                    len(encrypted_data)
                )
            )

            # Then send ciphertext
            send_all(
                conn,
                encrypted_data
            )

            print(
                "10 KB file sent successfully."
            )

            print(
                "\nPlaintext size :",
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
        # COMMAND 3
        # EXIT
        # =========================

        elif command == b"3":

            print("\nClient requested exit.")
            break


        else:

            print(
                "\nUnknown command:",
                command
            )


except ConnectionResetError:

    print(
        "\nClient connection was closed."
    )

except ConnectionError as e:

    print(
        "\nConnection error:",
        e
    )

finally:

    conn.close()
    server.close()

    print("\nServer stopped.")