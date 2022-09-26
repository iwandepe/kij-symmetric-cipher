import socket
import os
import sys
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

SEPARATOR = "\t"
BUFFER_SIZE = 4096
BLOCK_SIZE = 32

host = "localhost"
port = 5001
filename = "./static/file-example.txt"

def load_key():
    return open("./key.key", "rb").read()

def encrypt(filename, key):
    cipher = AES.new(key, AES.MODE_ECB)

    with open(filename, "rb") as file:
        file_data = file.read()
    
    encrypted_data = cipher.encrypt(pad(file_data, BLOCK_SIZE))

    filename = "./encrypted/file-example.txt"

    with open(filename, "wb") as file:
        file.write(encrypted_data)

key = load_key()

s = socket.socket()

print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")

encrypt(filename, key)
filename = "./encrypted/file-example.txt"
filesize = os.path.getsize(filename)

s.send(f"{filename}{SEPARATOR}{filesize}".encode())

with open(filename, "rb") as f:
    while True:
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
        s.sendall(bytes_read)

s.close()