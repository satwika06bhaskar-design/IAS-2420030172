import socket
import threading

HOST = "127.0.0.1"
PORT = 5000


# ==============================
# CAESAR CIPHER
# ==============================

def encrypt(text, key):
    result = ""

    for ch in text:
        if ch.isalpha():

            if ch.isupper():
                result += chr(
                    (ord(ch) - ord('A') + key) % 26
                    + ord('A')
                )

            else:
                result += chr(
                    (ord(ch) - ord('a') + key) % 26
                    + ord('a')
                )

        else:
            result += ch

    return result


def decrypt(text, key):
    return encrypt(text, -key)


# ==============================
# RECEIVE FROM SERVER
# ==============================

def receive_messages(client, key):

    while True:

        try:

            cipher = client.recv(1024).decode()

            if not cipher:
                print("\nServer disconnected.")
                break

            if cipher.lower() == "exit":
                print("\nServer ended the communication.")
                break

            plaintext = decrypt(cipher, key)

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

print("===================================")
print("       CAESAR CIPHER CLIENT")
print("===================================")

key = int(input("Enter Caesar Key: "))

print("\nConnected to server.")
print("Type messages below.")
print("Type 'exit' to stop.\n")


# Thread for receiving
receive_thread = threading.Thread(
    target=receive_messages,
    args=(client, key),
    daemon=True
)

receive_thread.start()


# ==============================
# SEND LOOP
# ==============================

while True:

    message = input("Client: ")

    if message.lower() == "exit":

        client.send("exit".encode())
        break

    cipher = encrypt(message, key)

    print("Encrypted Sent :", cipher)

    client.send(cipher.encode())


client.close()

print("\nClient stopped.")