import socket
import struct
import threading
import os
import io

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from pypdf import PdfReader
from docx import Document


HOST = "127.0.0.1"
PORT = 5000

KEY = b"12345678"
BLOCK_SIZE = 8


# ============================================================
# DES
# ============================================================

def pad(data):

    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    return data + bytes([padding]) * padding


def unpad(data):

    padding = data[-1]

    if padding < 1 or padding > BLOCK_SIZE:

        raise ValueError(
            "Invalid padding"
        )

    return data[:-padding]


def encrypt_data(data):

    iv = get_random_bytes(8)

    cipher = DES.new(
        KEY,
        DES.MODE_CBC,
        iv
    )

    ciphertext = cipher.encrypt(
        pad(data)
    )

    return iv + ciphertext


def decrypt_data(data):

    iv = data[:8]
    ciphertext = data[8:]

    cipher = DES.new(
        KEY,
        DES.MODE_CBC,
        iv
    )

    plaintext = cipher.decrypt(
        ciphertext
    )

    return unpad(plaintext)


# ============================================================
# SOCKET
# ============================================================

def receive_all(sock, size):

    data = bytearray()

    while len(data) < size:

        packet = sock.recv(
            min(65536, size - len(data))
        )

        if not packet:

            raise ConnectionError(
                "Connection closed."
            )

        data.extend(packet)

    return bytes(data)


def send_data(sock, data):

    sock.sendall(
        struct.pack("!Q", len(data))
    )

    sock.sendall(data)


def receive_data(sock):

    size = struct.unpack(
        "!Q",
        receive_all(sock, 8)
    )[0]

    return receive_all(sock, size)


def send_string(sock, text):

    send_data(
        sock,
        text.encode("utf-8")
    )


def receive_string(sock):

    return receive_data(sock).decode(
        "utf-8"
    )


# ============================================================
# READABLE CONTENT
# ============================================================

def get_readable_content(filename, data):

    extension = os.path.splitext(
        filename
    )[1].lower()

    # TXT / SOURCE FILES
    if extension in [
        ".txt",
        ".csv",
        ".py",
        ".java",
        ".c",
        ".cpp"
    ]:

        return data.decode(
            "utf-8",
            errors="replace"
        )


    # PDF
    elif extension == ".pdf":

        try:

            pdf = PdfReader(
                io.BytesIO(data)
            )

            text = ""

            for page in pdf.pages:

                page_text = page.extract_text()

                if page_text:

                    text += page_text + "\n"

            if text.strip():

                return text

            return "[PDF contains no extractable text]"

        except Exception as e:

            return f"[PDF extraction failed: {e}]"


    # WORD
    elif extension == ".docx":

        try:

            document = Document(
                io.BytesIO(data)
            )

            paragraphs = []

            for paragraph in document.paragraphs:

                paragraphs.append(
                    paragraph.text
                )

            text = "\n".join(
                paragraphs
            )

            if text.strip():

                return text

            return "[DOCX contains no readable text]"

        except Exception as e:

            return f"[DOCX extraction failed: {e}]"


    # BINARY
    else:

        return None


# ============================================================
# DISPLAY
# ============================================================

def display_transfer(
    side,
    direction,
    filename,
    plaintext,
    ciphertext
):

    print("\n")
    print("=" * 70)
    print(f"{side} - FILE TRANSFER")
    print("=" * 70)

    print(
        "Direction       :",
        direction
    )

    print(
        "File            :",
        filename
    )

    print(
        "Plaintext size  :",
        len(plaintext),
        "bytes"
    )

    print(
        "Ciphertext size :",
        len(ciphertext),
        "bytes"
    )

    readable = get_readable_content(
        filename,
        plaintext
    )

    if readable is not None:

        print(
            "\n----- PLAINTEXT / READABLE CONTENT -----"
        )

        if len(readable) > 5000:

            print(
                readable[:5000]
            )

            print(
                "\n...[remaining text not displayed]..."
            )

        else:

            print(
                readable
            )

    else:

        print(
            "\n----- PLAINTEXT / BINARY BYTES -----"
        )

        print(
            plaintext[:200]
        )

    print(
        "\n----- CIPHERTEXT -----"
    )

    print(
        ciphertext[:200].hex()
    )

    print("=" * 70)


# ============================================================
# SEND FILE
# ============================================================

def send_file(client):

    filename = input(
        "\nEnter file path to send: "
    ).strip()

    if not os.path.isfile(filename):

        print(
            "\nERROR: File not found."
        )

        return

    try:

        with open(
            filename,
            "rb"
        ) as file:

            plaintext = file.read()

        print(
            "\nEncrypting file..."
        )

        ciphertext = encrypt_data(
            plaintext
        )

        send_string(
            client,
            "FILE"
        )

        send_string(
            client,
            os.path.basename(filename)
        )

        send_data(
            client,
            ciphertext
        )

        display_transfer(
            "CLIENT",
            "CLIENT -> SERVER",
            os.path.basename(filename),
            plaintext,
            ciphertext
        )

        print(
            "\nFile encrypted and sent successfully."
        )

        print(
            "Received copy is NOT saved."
        )

    except Exception as e:

        print(
            "\nError:",
            e
        )


# ============================================================
# RECEIVE FILE
# ============================================================

def receive_file(client):

    print(
        "\nWaiting for encrypted file from Server..."
    )

    try:

        command = receive_string(
            client
        )

        if command != "FILE":

            print(
                "\nNo file received."
            )

            return

        filename = receive_string(
            client
        )

        ciphertext = receive_data(
            client
        )

        print(
            "\nEncrypted file received."
        )

        plaintext = decrypt_data(
            ciphertext
        )

        display_transfer(
            "CLIENT",
            "SERVER -> CLIENT",
            filename,
            plaintext,
            ciphertext
        )

        print(
            "\nFile decrypted successfully."
        )

        print(
            "Received copy is NOT saved."
        )

    except Exception as e:

        print(
            "\nError:",
            e
        )


# ============================================================
# LISTENER
# ============================================================

def listen_for_server(client):

    while True:

        try:

            command = receive_string(
                client
            )

            if command == "FILE":

                filename = receive_string(
                    client
                )

                ciphertext = receive_data(
                    client
                )

                plaintext = decrypt_data(
                    ciphertext
                )

                display_transfer(
                    "CLIENT",
                    "SERVER -> CLIENT",
                    filename,
                    plaintext,
                    ciphertext
                )

                print(
                    "\nFile decrypted successfully."
                )

                print(
                    "Received copy is NOT saved."
                )

        except:

            print(
                "\nServer connection closed."
            )

            break


# ============================================================
# CONNECT
# ============================================================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect(
    (HOST, PORT)
)


print("=" * 70)
print("              SDES / DES FILE TRANSFER CLIENT")
print("=" * 70)

print(
    "\nConnected to server."
)

print(
    "DES Key:",
    KEY.decode()
)


thread = threading.Thread(
    target=listen_for_server,
    args=(client,),
    daemon=True
)

thread.start()


# ============================================================
# CLIENT MENU
# ============================================================

while True:

    print("\n")
    print("=" * 70)
    print("CLIENT MENU")
    print("=" * 70)

    print("1. Encrypt and Send File to Server")
    print("2. Wait / Receive File from Server")
    print("3. Exit")

    print("=" * 70)

    choice = input(
        "Enter client choice: "
    ).strip()

    if choice == "1":

        send_file(client)

    elif choice == "2":

        print(
            "\nClient is ready to receive."
        )

        print(
            "Choose option 1 on the Server."
        )

        input(
            "\nPress ENTER when ready..."
        )

    elif choice == "3":

        try:

            send_string(
                client,
                "EXIT"
            )

        except:

            pass

        print(
            "\nClient stopped."
        )

        break

    else:

        print(
            "\nInvalid choice."
        )


client.close()