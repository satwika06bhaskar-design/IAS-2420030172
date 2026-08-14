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
                result += chr((ord(ch) - ord('A') + key) % 26 + ord('A'))
            else:
                result += chr((ord(ch) - ord('a') + key) % 26 + ord('a'))
        else:
            result += ch

    return result


def decrypt(text, key):
    return encrypt(text, -key)


# ==============================
# RECEIVE FROM CLIENT
# ==============================

def receive_messages(conn, key):

    while True:
        try:
            cipher = conn.recv(1024).decode()

            if not cipher:
                print("\nClient disconnected.")
                break

            if cipher.lower() == "exit":
                print("\nClient ended the communication.")
                break

            plaintext = decrypt(cipher, key)

            print("\n========== CLIENT -> SERVER ==========")
            print("Ciphertext :", cipher)
            print("Plaintext  :", plaintext)
            print("======================================")

        except:
            break


# ==============================
# SERVER
# ==============================

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen(1)

print("===================================")
print("       CAESAR CIPHER SERVER")
print("===================================")

print("Waiting for client...")

conn, addr = server.accept()

print("Connected to:", addr)

key = int(input("Enter Caesar Key: "))

print("\nServer is ready.")
print("Type messages below.")
print("Type 'exit' to stop.\n")


# Thread for receiving
receive_thread = threading.Thread(
    target=receive_messages,
    args=(conn, key),
    daemon=True
)

receive_thread.start()


# ==============================
# SEND LOOP
# ==============================

while True:

    message = input("Server: ")

    if message.lower() == "exit":

        conn.send("exit".encode())
        break

    cipher = encrypt(message, key)

    print("Encrypted Sent :", cipher)

    conn.send(cipher.encode())


conn.close()
server.close()

print("\nServer stopped.")