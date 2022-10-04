import os
import sys
import socket
import select

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, AES
from collections import namedtuple
import yaml


def load_key():
    return open(f"{cfg.ABSOLUTEPATH}/server/key.key", "rb").read()


def prepare_connection():
    global s, client_socket

    s = socket.socket()
    s.bind((cfg.SERVER_HOST, cfg.SERVER_PORT))

    s.listen(5)
    print(f"[*] Listening as {cfg.SERVER_HOST}:{cfg.SERVER_PORT}")


def decrypt(dst_path, key, AES_MODE=AES.MODE_ECB):
    cipher = AES.new(key, AES_MODE)

    with open(dst_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = unpad(cipher.decrypt(encrypted_data), cfg.BLOCK_SIZE)

    with open(dst_path, "wb") as file:
        file.write(decrypted_data)


def read_config(path):
    with open(path, "r") as stream:
        try:
            global cfg
            dict_cfg = yaml.safe_load(stream)
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
        return 'MODE_OPENPGP'
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


if __name__ == "__main__":
    read_config("D:\Coll\\7_7-KIJ-C\kij\config\config.yml")
    key = load_key()

    files = ['small.txt', 'big.txt']
    
    # for filename in files:
    try:
        prepare_connection()
        client_socket, address = s.accept()
        print(f"[*] {address} is connected.")

        while (True):
        
            received = client_socket.recv(cfg.BUFFER_SIZE).decode()
                
            received_path, enc_size, mode = received.split(cfg.SEPARATOR)
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

            decrypt(dst_path, key, int(mode))


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