# Exactly 1 MB
data_1mb = b"CLIENT TO SERVER - SDES FILE TRANSFER\n"

with open("client_1MB.txt", "wb") as f:
    while f.tell() < 1024 * 1024:
        remaining = 1024 * 1024 - f.tell()
        f.write(data_1mb[:remaining])

# Exactly 10 KB
data_10kb = b"SERVER TO CLIENT - SDES FILE TRANSFER\n"

with open("server_10KB.txt", "wb") as f:
    while f.tell() < 10 * 1024:
        remaining = 10 * 1024 - f.tell()
        f.write(data_10kb[:remaining])

print("Files created successfully.")