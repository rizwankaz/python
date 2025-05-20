state = [[0x0 for _ in range(5)] for _ in range(5)]

k = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

def rot(value: int, n: int) -> int:
    return ((value << (64 - n)) | (value >> n)) & 0xFFFFFFFFFFFFFFFF

def pad(message: bytes) -> bytes:
    padded = message + b'\x01'
    while (len(padded)*8) % 1088 != 0:
        padded += b'\x00'
    return padded[:-1] + b'\x80'

def theta(state):
    C = [0]*5
    D = [0]*5
    for x in range(5):
        C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
    for x in range(5):
        D[x] = C[(x-1)%5] ^ rot(C[(x+1)%5], 1)
    for x in range(5):
        for y in range(5):
            state[x][y] ^= D[x]
    return state

def rho_pi(state):
    new_state = [[0]*5 for _ in range(5)]
    offsets = [
        [ 0, 36,  3, 41, 18],
        [ 1, 44, 10, 45,  2],
        [62,  6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39,  8, 14]
    ]
    for x in range(5):
        for y in range(5):
            new_state[y][(2*x + 3*y) % 5] = rot(state[x][y], offsets[x][y])
    return new_state

def chi(state):
    new_state = [[0]*5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            new_state[x][y] = state[x][y] ^ (
                (~state[(x+1)%5][y]) & state[(x+2)%5][y])
    return new_state

def iota(state, round_num):
    state[0][0] ^= k[round_num]
    return state

def keccak_f(state):
    for round_num in range(24):
        state = theta(state)
        state = rho_pi(state)
        state = chi(state)
        state = iota(state, round_num)
    return state

def keccak256(message: bytes) -> bytes:
    state = [[0]*5 for _ in range(5)]
    padded = pad(message)
    for i in range(0, len(padded), 136):
        block = padded[i:i+136] + bytes(136 - len(padded[i:i+136]))
        for x in range(5):
            for y in range(5):
                if 5*x + y < 17:
                    state[x][y] ^= int.from_bytes(
                        block[(5*x + y)*8:(5*x + y +1)*8], 'little')
        state = keccak_f(state)
    output = b''
    for x in range(5):
        for y in range(5):
            if 5*x + y < 4:
                output += state[x][y].to_bytes(8, 'little')
    return output[:32]

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python keccak256.py <message>")
        sys.exit(1)
    message = sys.argv[1].encode('utf-8')
    digest = keccak256(message)
    print(digest.hex())