IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
]

def blake2s_init(digest_size=32, key=b''):
    h = IV.copy()
    param_block = (digest_size | (len(key) << 8) | (0x01 << 16) | (0x01 << 24))
    h[0] ^= param_block
    return {
        'h': h,
        't': [0, 0],
        'buffer': bytearray(64),
        'digest_size': digest_size,
        'key': key.ljust(32, b'\x00')[:32]
    }

def blake2s_pad(message: bytes):
    padded = bytearray(message)
    pad_len = (-len(message)) % 64
    padded += b'\x00' * pad_len
    padded[-8:] = (len(message) * 8).to_bytes(8, 'little')
    return padded

def G(a: int, b: int, c: int, d: int, mx: int, my: int):
    a = (a + b + mx) & 0xFFFFFFFF
    d = ((d ^ a) << 16 | (d ^ a) >> 16) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = ((b ^ c) << 12 | (b ^ c) >> 20) & 0xFFFFFFFF
    a = (a + b + my) & 0xFFFFFFFF
    d = ((d ^ a) << 8 | (d ^ a) >> 24) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = ((b ^ c) << 7 | (b ^ c) >> 25) & 0xFFFFFFFF
    return a, b, c, d

def compress(ctx, block, last):
    m = [int.from_bytes(block[i*4:(i+1)*4], 'little') for i in range(16)]
    v = ctx['h'] + IV + [
        ctx['t'][0] ^ 0xFFFFFFFF, ctx['t'][1],
        0xFFFFFFFF if last else 0, 0
    ]
    
    for round in range(10):
        v[0], v[4], v[8], v[12] = G(v[0], v[4], v[8], v[12], m[0], m[1])
        v[1], v[5], v[9], v[13] = G(v[1], v[5], v[9], v[13], m[2], m[3])
        v[2], v[6], v[10], v[14] = G(v[2], v[6], v[10], v[14], m[4], m[5])
        v[3], v[7], v[11], v[15] = G(v[3], v[7], v[11], v[15], m[6], m[7])
        
        v[0], v[5], v[10], v[15] = G(v[0], v[5], v[10], v[15], m[8], m[9])
        v[1], v[6], v[11], v[12] = G(v[1], v[6], v[11], v[12], m[10], m[11])
        v[2], v[7], v[8], v[13] = G(v[2], v[7], v[8], v[13], m[12], m[13])
        v[3], v[4], v[9], v[14] = G(v[3], v[4], v[9], v[14], m[14], m[15])

    for i in range(8):
        ctx['h'][i] ^= v[i] ^ v[i+8]

def blake2s(message: bytes, digest_size=32, key=b'') -> bytes:
    ctx = blake2s_init(digest_size, key)
    padded = blake2s_pad(message)
    
    for i in range(0, len(padded), 64):
        ctx['t'][0] += 64
        if ctx['t'][0] < 64:
            ctx['t'][1] += 1
        compress(ctx, padded[i:i+64], i == len(padded)-64)
    
    return b''.join(h.to_bytes(4, 'little') for h in ctx['h'][:digest_size//4])

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python blake2s.py <message>")
        sys.exit(1)
    message = sys.argv[1].encode('utf-8')
    digest = blake2s(message)
    print(digest.hex())