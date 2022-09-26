import socket
import os
import sys

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001

BUFFER_SIZE = 4096
SEPARATOR = "\t"

s = socket.socket()
s.bind((SERVER_HOST, SERVER_PORT))

s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

client_socket, address = s.accept() 
print(f"[+] {address} is connected.")

received = client_socket.recv(BUFFER_SIZE).decode()

filename, filesize = received.split(SEPARATOR)
filename = os.path.basename(filename)
filesize = int(filesize)

with open(filename, "wb") as f:
    while True:
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            break

        f.write(bytes_read)

client_socket.close()
s.close()