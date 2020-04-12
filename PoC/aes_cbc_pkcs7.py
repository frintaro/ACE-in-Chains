#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, binascii, hashlib, hmac
from Crypto import Random
from Crypto.Cipher import AES
from getpass import getpass

fixed_key = b"CBC attack PoC"

def is_valid_args(argv):
    return len(argv) == 3 and (argv[1] == 'e' or argv[1] == 'd') and os.path.isfile(argv[2])

def gen_IV():
    return Random.new().read(AES.block_size)

def gen_key(password):
    return binascii.unhexlify(hmac.new(fixed_key, password, hashlib.sha256).hexdigest())

def padding(s):
    i = AES.block_size - len(s) % AES.block_size
    pad = chr(i).encode('utf-8') * i
    return s + pad

def unpadding(s):
    return s[:-s[-1]]

def is_valid_padding(s):
    i = s[-1]
    return 0 < i and i <= AES.block_size and s[-1:]*i == s[-i:]

def encrypt(p, key, IV):
    return AES.new(key, AES.MODE_CBC, IV).encrypt(padding(p))

def decrypt(c, key):
    IV = c[:AES.block_size]
    cipher = c[AES.block_size:]
    return AES.new(key, AES.MODE_CBC, IV).decrypt(cipher)

def write_file(filename, content):
    try:
        f = open(filename, 'wb')
        f.write(content)
        f.close()
        return True
    except:
        return False

def main(argv):
    if not is_valid_args(argv):
        print("[-] Usage:\n\t$ %s [e Target_file|d Target_file]" % argv[0])
        quit()

    option = argv[1]
    filename = argv[2]
    try:
        f = open(filename, 'rb')
        content = f.read()
        f.close()
    except IOError:
        print("[-] Failed to open the target file:", filename)
        quit()

    password = getpass("Input password: ").encode('utf-8')
    key = gen_key(password)

    if option == 'e':
        IV = gen_IV()
        cipher = encrypt(content, key, IV)
        if write_file(filename, IV+cipher):
            print("[+] Encryption is done.")
        else:
            print("[-] Failed to create a encrypted file.")
    else:
        if len(content) % AES.block_size != 0:
            print("[-] Encrypted strings must be a multiple of %d in length." % AES.block_size)
            quit()
        decrypted = decrypt(content, key)
        if not is_valid_padding(decrypted):
            print("[-] Incorrect pkcs7 padding.")
            quit()
        plain = unpadding(decrypted)
        if write_file(filename, plain):
            print("[+] Decryption is done.")
        else:
            print("[-] Failed to create a decrypted file.")

if __name__ == "__main__":
    main(sys.argv)
