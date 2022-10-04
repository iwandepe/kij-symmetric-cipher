import os
import sys
import yaml
import socket
import select

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, AES
from collections import namedtuple

def load_key():
    return open(f"{cfg.ABSOLUTEPATH}/server/key.key", "rb").read()


def prepare_connection():
    global s, client_socket

    s = socket.socket()
    s.bind((cfg.SERVER_HOST, cfg.SERVER_PORT))

    s.listen(5)
    print(f"[*] Listening as {cfg.SERVER_HOST}:{cfg.SERVER_PORT}")


def decrypt(filename, key):
    cipher = AES.new(key, AES.MODE_ECB)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = unpad(cipher.decrypt(encrypted_data), cfg.BLOCK_SIZE)

    with open(filename, "wb") as file:
        file.write(decrypted_data)


def read_config(path):
    with open(path, "r") as stream:
        try:
            global cfg
            dict_cfg = yaml.safe_load(stream)
            cfg = namedtuple("MyConf", dict_cfg.keys())(*dict_cfg.values())
        except yaml.YAMLError as exc:
            print(exc)


if __name__ == "__main__":
    read_config("D:\Coll\\7_7-KIJ-C\kij\config\config.yml")
    key = load_key()
    
    prepare_connection()
    
    try:
        client_socket, address = s.accept()
        print(f"[*] {address} is connected.")
    
        received = client_socket.recv(cfg.BUFFER_SIZE).decode()
            
        print(f"[*] Received: {received}")
        filename, filesize = received.split('\t')
        filename = f"{cfg.ABSOLUTEPATH}/server/static/" + os.path.basename(filename)

        filesize = int(filesize)

        with open(filename, "wb") as f:
            while True:
                bytes_read = client_socket.recv(cfg.BUFFER_SIZE)
                if not bytes_read:
                    break

                f.write(bytes_read)

        decrypt(filename, key)
        print(f"[*] Received data {filename}\n\n")

        client_socket.close()
        print(f"[*] {address} is disconnected.\n\n")

    except KeyboardInterrupt:
        print('[*] Exiting...')
        s.close()
        sys.exit(0)