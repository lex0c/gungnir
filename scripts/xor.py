#!/usr/bin/env python

import sys

def xor(x_str):
    result = []

    for x in x_str:
        xor_char = ord(x) ^ 0xfe
        hex_char = hex(xor_char)[2:]  # remove prefix 0x
        result.append(f'\\x{hex_char}')

    return ''.join(result)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Use: {sys.argv[0]} <string>")
        sys.exit(1)

    s = sys.argv[1]
    print(xor(s))

