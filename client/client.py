import os
import sys
import socket
import json
from analizer import Analizer
from pathlib import Path

from base64 import b64encode
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, AES
from collections import namedtuple
import yaml
from RC4 import RC4_encryption
import numpy as np

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes

def load_key():
    return open(f"{cfg.ABSOLUTEPATH}/client/key.key", "rb").read()


def prepare_connection():
    global s, client_socket

    s = socket.socket()
    print(f"[*] Connecting to {cfg.SERVER_HOST}:{cfg.SERVER_PORT}.")
    s.connect((cfg.SERVER_HOST, cfg.SERVER_PORT))
    print("[*] Connected.")


def encrypt(src_path, key, AES_MODE=AES.MODE_ECB):
    cipher = AES.new(key, AES_MODE)

    with open(src_path, "rb") as file:
        file_data = file.read()

    lizer = Analizer(src_path, "AES", AES_MODE)

    lizer.startTimer()
    encrypted_data = cipher.encrypt(pad(file_data, 16))
    
    iv = None
    if (AES_MODE == 6):
        iv = b64encode(cipher.nonce).decode('utf-8')
    elif (AES_MODE != 1):
        iv = b64encode(cipher.iv).decode('utf-8')

    lizer.endTimer()

    try:
        lizer.addToRecord()
    except Exception as exc:
        print( '[!] Record failed to save :', exc)

    dst_path = f"{cfg.ABSOLUTEPATH}/client/encrypted/{cfg.TARGET_FILE}".replace('.txt', '.bin')

    with open(dst_path, "wb") as file:
        file.write(encrypted_data)

    return iv

def encryptRC4(src_path, key):
    with open(src_path, "r") as file:
        file_data = file.read()

    lizer = Analizer(src_path, "RC4")

    lizer.startTimer()
    RC4 = RC4_encryption(file_data, key)

    lizer.endTimer()

    try:
        lizer.addToRecord()
    except Exception as exc:
        print( '[!] Record failed to save :', exc)

    dst_path = f"{cfg.ABSOLUTEPATH}/client/encrypted/{cfg.TARGET_FILE}".replace('.txt', '.bin')

    final_encrypted = RC4.result
    with open(dst_path, "w", encoding="utf-8") as file:
        file.write(final_encrypted)

    return RC4.iv

def encUtilRC4(key,p):
    return ARC4.new(key).encrypt(p)


def encryptRC4lib(src_path, key):
    key=b'\xe39-b\x87\x8c\xe2\x19\x0c\x90\x10^\xc0\xb7\xea\xe9\x16\xfc00\xe0\x0b\xda\xad3\xe3\xbe\x9c\xc9e\xdco'

    with open(src_path, "r") as file:
        file_data = file.read()

    lizer = Analizer(src_path, "RC4lib")

    lizer.startTimer()
    # RC4 = RC4_encryption(file_data, key)
    RC4 = encUtilRC4(key, file_data.encode())

    lizer.endTimer()

    try:
        lizer.addToRecord()
    except Exception as exc:
        print( '[!] Record failed to save :', exc)

    dst_path = f"{cfg.ABSOLUTEPATH}/client/encrypted/{cfg.TARGET_FILE}".replace('.txt', '.bin')

    final_encrypted = RC4.decode()
    with open(dst_path, "w", encoding="utf-8") as file:
        file.write(final_encrypted)

    return None

def encryptDES(src_path, key):
    cipher = DES.new(key, DES.MODE_ECB)

    lizer = Analizer(src_path, "DES", DES.MODE_ECB)

    lizer.startTimer()

    with open(src_path, "rb") as file:
        file_data = file.read()

    encrypted_data = cipher.encrypt(pad(file_data, 8))

    lizer.endTimer()

    try:
        lizer.addToRecord()
    except Exception as exc:
        print( '[!] Record failed to save :', exc)

    dst_path = f"{cfg.ABSOLUTEPATH}/client/encrypted/{cfg.TARGET_FILE}".replace('.txt', '.bin')

    with open(dst_path, "wb") as file:
        file.write(encrypted_data)
        
    return None

def preparing_key_array(s):
    return [ord(c) for c in s]

def read_config(path):
    with open(path, "r") as stream:
        try:
            global cfg
            dict_cfg = yaml.safe_load(stream)
            if("ABSOLUTEPATH" not in dict_cfg):
                dict_cfg["ABSOLUTEPATH"] = str(Path(os.path.dirname(os.path.realpath(__file__))).parent.absolute())
                
            cfg = namedtuple("MyConf", dict_cfg.keys())(*dict_cfg.values())
        except yaml.YAMLError as exc:
            print(exc)


if __name__ == "__main__":
    base_path = str(Path(os.path.dirname(os.path.realpath(__file__))).parent.absolute())
    read_config(base_path + "/config/config.yml")
    key = load_key()

    # modes = [1,2,3,5,6]
    # files = ['small.txt', 'big.txt']
    filename = cfg.TARGET_FILE
    mode = cfg.MODE
    method = cfg.METHOD

    # for filename in files:
    try:
        prepare_connection()

        filepath = f"{cfg.ABSOLUTEPATH}/client/static/{filename}"

        if(method == "AES"):
            iv = encrypt(filepath, key, mode)
        elif(method == "RC4"):
            iv = encryptRC4(filepath, key)
        elif(method == "RC4lib"):
            iv = encryptRC4lib(filepath, key)
        elif(method == "DES"):
            iv = encryptDES(filepath, "12345678".encode())
        else:
            print("Invalid method")
            sys.exit(1)

        realname = f"{cfg.ABSOLUTEPATH}/client/encrypted/{filename}"
        enc_path = realname.replace(".txt", ".bin")
        enc_size = os.path.getsize(enc_path)

        if iv is None:
            iv = "None"
        
        s.send(f"{realname}{cfg.SEPARATOR}{enc_size}{cfg.SEPARATOR}{iv}".encode())

        with open(enc_path, "rb") as f:
            while True:
                bytes_read = f.read(cfg.BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)

    except Exception as exc:
        print(exc)
    s.close()
