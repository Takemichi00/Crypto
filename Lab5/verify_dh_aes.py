#!/usr/bin/env python3
"""Verificare independentă pentru Sarcina 3: derivarea cheii AES-256 din secretul
Diffie-Hellman și criptarea unui bloc cu AES-256 (implementare proprie, fără
biblioteci externe de criptare). Compară rezultatul cu cel produs de programul Go."""
import hashlib

def load(f):
    d = {}
    for line in open(f):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            d[k] = v
    return d

# Standard AES S-box built from GF(2^8) inverse + FIPS-197 affine transform
def gxtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff

def gmul(a, b):
    res = 0
    while b:
        if b & 1:
            res ^= a
        b >>= 1
        a = gxtime(a)
    return res

def gen_sbox2():
    sbox = []
    exp = [0]*512
    log = [0]*256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = gmul(x, 3)
    for i in range(255, 512):
        exp[i] = exp[i - 255]                       # wrap table so exp[255]=exp[0]=1
    for i in range(256):
        inv = 0 if i == 0 else exp[255 - log[i]]
        b = inv
        r = b
        for sh in (1, 2, 3, 4):                       # FIPS-197 affine transform
            r ^= ((b << sh) | (b >> (8 - sh))) & 0xff
        sbox.append(r ^ 0x63)
    return sbox

SB = gen_sbox2()
assert SB[0x00] == 0x63 and SB[0x53] == 0xed and SB[0x01] == 0x7c

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]

def expand_key256(key):
    w = [list(key[i*4:(i+1)*4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i-1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SB[b] for b in t]
            t[0] ^= RCON[i//8 - 1]
        elif i % 8 == 4:
            t = [SB[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])
    return [sum(w[r*4:r*4+4], []) for r in range(15)]

def aes_encrypt_block(block, round_keys):
    # state s[] is column-major: s[4*c+r] = byte at row r, column c
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    def sub_shift_mix(sr):
        t = [SB[b] for b in sr]                                   # SubBytes
        # ShiftRows (row i shifted left by i) on column-major layout
        o = list(t)
        for i in (1, 2, 3):
            row = [t[r + 4*c] for r in range(4) for c in range(4) if False]
            row = [t[i + 4*c] for c in range(4)]
            row = row[i:] + row[:i]
            for c in range(4):
                o[i + 4*c] = row[c]
        ns = [0]*16                                               # MixColumns
        for c in range(4):
            a = [o[4*c], o[4*c+1], o[4*c+2], o[4*c+3]]
            ns[4*c+0] = gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3]
            ns[4*c+1] = a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3]
            ns[4*c+2] = a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3)
            ns[4*c+3] = gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2)
        return ns
    for rnd in range(13):
        s = sub_shift_mix(s)
        s = [b ^ k for b, k in zip(s, round_keys[rnd+1])]
    # last round: no MixColumns
    t = [SB[b] for b in s]
    o = list(t)
    for i in (1, 2, 3):
        row = [t[i + 4*c] for c in range(4)]
        row = row[i:] + row[:i]
        for c in range(4):
            o[i + 4*c] = row[c]
    s = [b ^ k for b, k in zip(o, round_keys[14])]
    return bytes(s)

# FIPS-197 known-answer test for AES-256
kt_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
kt_pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
ct = aes_encrypt_block(list(kt_pt), expand_key256(kt_key))
assert ct.hex() == "8ea2b7ca516745bfeafc49904b496089", ct.hex()
print("KAT AES-256 FIPS-197: OK ->", ct.hex())

h = load("dh_params.txt")
K = int(h["K"])
key = hashlib.sha256(K.to_bytes(256, "big")).digest()
print("AES key hex:", key.hex())
pt = b"Nume Prenume".ljust(16, b"\x00")
rk = expand_key256(key)
ct = aes_encrypt_block(list(pt), rk)
print("plaintext :", pt.hex(), pt)
print("ciphertext:", ct.hex())
