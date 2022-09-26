import socket
import os   

SEPARATOR = "\t"
BUFFER_SIZE = 4096

host = "192.168.0.117"
port = 5001
filename = "../static/file-example.txt"
filesize = os.path.getsize(filename)

s = socket.socket()

print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")

s.send(f"{filename}{SEPARATOR}{filesize}".encode())

with open(filename, "rb") as f:
    while True:
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
        s.sendall(bytes_read)

s.close()