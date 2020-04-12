# ACE in Chains : How Risky is CBC Encryption of Binary Executable Files ?

PoC files for ACNS 2020.

## aes_cbc_pkcs7.py
A sample encryption/decryption program using AES-CBC and PKCS 7 padding with no tamper detection. A key used to the encryption/decryption is generated from user input and hmac-sha256 with a fixed-value. Then, the program encrypts and/or decrypts the target file. In the encryption, IV is randomly generated and inserted before the encrypted contents (i.e., the encrypted file size becomes sixteen bytes bigger than the original file). Note that the program requires [pycrypto](https://pypi.org/project/pycrypto/) library.

```
Usage: $ python3 aes_cbc_pkcs7.py option target-file-name
Option:
  e  encryption
  d  decryption
```

## attack_linux.py
Exploit for Linux x86 and x86-64 executable files. It uses the known-plaintext as the first block. Each payload snippet skips the fifth and eighth bytes which are not fixed. The location to inject that you input should be hex value.

```
Usage: $ python3 attack_linux.py target-encrypted-file
```

## attack_windows.py
Exploit for Windows executable files both for 32- and 64-bit. It uses the known-plaintext as the second block. The location to inject that you input should be hex value.

```
Usage: $ python3 attack_windows.py target-encrypted-file
```
