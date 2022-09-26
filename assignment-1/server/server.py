import socket
import os
import sys
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001

BUFFER_SIZE = 4096
SEPARATOR = "\t"
BLOCK_SIZE = 32

def load_key():
    return open("./key.key", "rb").read()

s = socket.socket()
s.bind((SERVER_HOST, SERVER_PORT))

s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

client_socket, address = s.accept() 
print(f"[+] {address} is connected.")

received = client_socket.recv(BUFFER_SIZE).decode()

key = load_key()
def decrypt(filename, key):
    cipher = AES.new(key, AES.MODE_ECB)
    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

    with open(filename, "wb") as file:
        file.write(decrypted_data)

filename, filesize = received.split(SEPARATOR)
filename = './static/' + os.path.basename(filename)
filesize = int(filesize)

with open(filename, "wb") as f:
    while True:
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            break

        f.write(bytes_read)

decrypt(filename, key)
client_socket.close()
s.close()