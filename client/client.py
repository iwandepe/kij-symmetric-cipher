import socket
import os
import sys
from analizer import Analizer
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

SEPARATOR = "\t"
BUFFER_SIZE = 4096
BLOCK_SIZE = 32

TARGET_FILE1 = 'file-example.txt'
TARGET_FILE2 = 'kabupaten.txt'
TARGET_FILE = TARGET_FILE2 # select ur target here

host = "localhost"
port = 5001
absolutePath = ''
relativePath = '.'
filename = f"{absolutePath}{relativePath}/static/{TARGET_FILE}"

# ===== begin:allamDir =====
# absolutePath = '/home/allam/dev-project/kij'
# relativePath = '/assignment-1/client'
# filename = f"{absolutePath}{relativePath}/static/{TARGET_FILE}"
# ===== end:allamDir =====

def load_key():
    key = open(f"{absolutePath}{relativePath}/key.key", "rb").read()
    print(f"[*] Key loaded: {key}")
    return key

def encrypt(filename, key, AES_MODE=AES.MODE_ECB):
    cipher = AES.new(key, AES_MODE)

    with open(filename, "rb") as file:
        file_data = file.read()
    
    # ===== begin:timer block =====
    lizer = Analizer('ECB', './data/record.csv', filename)
    lizer.startTimer()
    # ===== end:timer block =====

    encrypted_data = cipher.encrypt(pad(file_data, BLOCK_SIZE))

    # ===== begin:timer block =====
    lizer.endTimer()
    try:
        lizer.addToRecord()
    finally:
        print( 'record failed to save' )
    # ===== end:timer block =====

    filename = f"{absolutePath}{relativePath}/encrypted/{TARGET_FILE}"

    with open(filename, "wb") as file:
        file.write(encrypted_data)
    

key = load_key()

s = socket.socket()

print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")

encrypt(filename, key)
filename = f"{absolutePath}{relativePath}/encrypted/{TARGET_FILE}"
filesize = os.path.getsize(filename)

print(f"{filename}{SEPARATOR}{filesize}")

s.send(f"{filename}{SEPARATOR}{filesize}".encode())

with open(filename, "rb") as f:
    while True:
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
        s.sendall(bytes_read)

s.close()