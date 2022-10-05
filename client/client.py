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


def load_key():
    return open(f"{cfg.ABSOLUTEPATH}/client/key.key", "rb").read()


def prepare_connection():
    global s, client_socket

    s = socket.socket()
    print(f"[*] Connecting to {cfg.SERVER_HOST}:{cfg.SERVER_PORT}.")
    s.connect((cfg.SERVER_HOST, cfg.SERVER_PORT))
    print("[*] Connected.")


def encrypt(src_path, key, AES_MODE=AES.MODE_ECB) -> str:
    cipher = AES.new(key, AES_MODE)

    with open(src_path, "rb") as file:
        file_data = file.read()

    lizer = Analizer(src_path, AES_MODE)

    lizer.startTimer()
    encrypted_data = cipher.encrypt(pad(file_data, cfg.BLOCK_SIZE))
    
    nonce = None
    if (AES_MODE == 6):
        nonce = b64encode(cipher.nonce).decode('utf-8')

    lizer.endTimer()

    try:
        lizer.addToRecord()
    except Exception as exc:
        print( '[!] Record failed to save :', exc)

    dst_path = f"{cfg.ABSOLUTEPATH}/client/encrypted/{cfg.TARGET_FILE}".replace('.txt', '.bin')

    with open(dst_path, "wb") as file:
        file.write(encrypted_data)

    return nonce


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

    # for filename in files:
    try:
        prepare_connection()

        filepath = f"{cfg.ABSOLUTEPATH}/client/static/{filename}"

        nonce = encrypt(filepath, key, mode)

        realname = f"{cfg.ABSOLUTEPATH}/client/encrypted/{filename}"
        enc_path = realname.replace('.txt', '.bin')
        enc_size = os.path.getsize(enc_path)

        if nonce is None:
            nonce = 'ECB'
        s.send(f"{realname}{cfg.SEPARATOR}{enc_size}{cfg.SEPARATOR}{mode}{cfg.SEPARATOR}{nonce}".encode())

        with open(enc_path, "rb") as f:
            while True:
                bytes_read = f.read(cfg.BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)

    except Exception as exc:
        print(exc)
    s.close()
