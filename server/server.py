import os
import sys
import socket
import select
from pathlib import Path

from base64 import b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, AES
from collections import namedtuple
import yaml
from Crypto.Random import get_random_bytes

from Crypto.Cipher import ARC4

from RC4 import RC4_encryption


def load_key():
    return open(f"{cfg.ABSOLUTEPATH}/server/key.key", "rb").read()


def prepare_connection():
    global s, client_socket

    s = socket.socket()
    s.bind((cfg.SERVER_HOST, cfg.SERVER_PORT))

    s.listen(5)
    print(f"[*] Listening as {cfg.SERVER_HOST}:{cfg.SERVER_PORT}")


def decryptAES(dst_path, key, AES_MODE=AES.MODE_ECB, nonce=None, iv=None):
    cipher = None
    if (int(mode) == 1):
        cipher = AES.new(key, AES_MODE)
    elif (int(mode) == 6):
        cipher = AES.new(key, AES_MODE, nonce=b64decode(nonce))
    else:
        cipher = AES.new(key, AES_MODE, iv=b64decode(iv))

    with open(dst_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)

    with open(dst_path, "wb") as file:
        file.write(decrypted_data)

def decryptRC4(dst_path, key):
    with open(dst_path, "rb", encoding="utf-8") as file:
        encrypted_data = file.read()
    
    RC4 = RC4_encryption(encrypted_data, key)
    decrypted_data = RC4.result

    with open(dst_path, "wb") as file:
        file.write(decrypted_data)

def decUtilRC4(key,msg):
    return ARC4.new(key).decrypt(msg)

def decryptRC4lib(dst_path, key):
    with open(dst_path, "rb") as file:
        encrypted_data = file.read()
    
    # RC4 = RC4_encryption(encrypted_data, key)
    # cipher = ARC4.new(tempkey)
    # msg = nonce + cipher.decrypt(b'Open the pod bay doors, HAL')
    decrypted_data = decUtilRC4(key, encrypted_data)

    with open(dst_path, "wb") as file:
        file.write(decrypted_data)

def decryptDES(dst_path, key, DES_MODE=DES.MODE_ECB, nonce=None, iv=None):
    nonce = b''

    if (int(mode) == 1):
        cipher = DES.new(key, DES_MODE)
    elif (int(mode) == 6):
        cipher = DES.new(key, DES_MODE, nonce=(nonce))
    else:
        cipher = DES.new(key, DES_MODE, iv=b64decode(iv))

    with open(dst_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = unpad(cipher.decrypt(encrypted_data), 8)

    with open(dst_path, "wb") as file:
        file.write(decrypted_data)

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


def translate_mode(mode):
    if(mode==1): 
        return 'MODE_ECB'
    if(mode==2): 
        return 'MODE_CBC'
    if(mode==3): 
        return 'MODE_CFB'
    if(mode==5): 
        return 'MODE_OFB'
    if(mode==6): 
        return 'MODE_CTR'
    if(mode==7): 
        return 'MODE_RC4'
    if(mode==8): 
        return 'MODE_CCM'
    if(mode==9): 
        return 'MODE_EAX'
    if(mode==10): 
        return 'MODE_SIV'
    if(mode==11): 
        return 'MODE_GCM'
    if(mode==12): 
        return 'MODE_OCB'
    if(mode==13): 
        return 'MODE_RC4lib'
    if(mode==14):
        return 'MODE_DES'


if __name__ == "__main__":
    base_path = str(Path(os.path.dirname(os.path.realpath(__file__))).parent.absolute())
    read_config(base_path + "/config/config.yml")
    key = load_key()
    keyDES = "12345678".encode()

    method = cfg.METHOD
    mode = cfg.MODE

    if(method == "RC4"):
        mode = 7
    elif(method == "RC4lib"):
        mode = 13

    files = ['small.txt', 'big.txt']
    
    # for filename in files:
    try:
        prepare_connection()
        client_socket, address = s.accept()
        print(f"[*] {address} is connected.")

        while (True):
        
            received = client_socket.recv(cfg.BUFFER_SIZE).decode()

            received_path, enc_size, iv = received.split(cfg.SEPARATOR)
            dst_path = f"{cfg.ABSOLUTEPATH}/server/static/" + os.path.basename(received_path)

            print(f"[*] Received {received}")
            print(f"[*] MODE: {translate_mode(int(mode))}")
            print('\n')

            with open(dst_path, "wb") as f:
                while True:
                    bytes_read = client_socket.recv(cfg.BUFFER_SIZE)
                    
                    if not bytes_read:
                        break
                    f.write(bytes_read)

            if (method == "AES"):
                if (int(mode) == 1):
                    decryptAES(dst_path, key, int(mode))
                elif (int(mode) == 6):
                    decryptAES(dst_path, key, int(mode), nonce=iv),
                else:
                    decryptAES(dst_path, key, int(mode), iv=iv)
            elif (method == "RC4"):
                decryptRC4(dst_path, key)
            elif (method == "RC4lib"):
                decryptRC4lib(dst_path, key)
            elif (method == "DES"):
                if (int(mode) == 1):
                    decryptDES(dst_path, keyDES, int(mode))
                elif (int(mode) == 6):
                    decryptDES(dst_path, keyDES, int(mode), nonce=iv),
                else:
                    decryptDES(dst_path, keyDES, int(mode), iv=iv)
            else:
                print("Invalid method")
                sys.exit(1)


            if(not cfg.RECURSIVE):
                client_socket.close()
                break
            else:
                print(f"[*] {address} is disconnected.\n\n")
                # client_socket.close()
                # s.close()

    except KeyboardInterrupt:
        print('[*] Exiting...')
        s.close()
        sys.exit(0)
    
    s.close()