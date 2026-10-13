#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Implementare MD4 (RFC 1320) in Python pur, folosita pentru hash-ul NTLM.

NTLM(password) = MD4(UTF-16LE(password)).
Verificata cu vectorii de test din RFC 1320:
  MD4("")       = 31d6cfe0d16ae931b73c59d7e0c089c0
  MD4("abc")    = a448017aaf21d8525fc10ae87aa6729d
  MD4(message digest) = 9e107d9d372bb6826bd81d3542a419d6
"""

import struct


def _rol(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(msg: bytes) -> bytes:
    # padding
    ml = len(msg) * 8
    msg += b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", ml & 0xFFFFFFFFFFFFFFFF)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[i:i + 64]))
        A, B, C, D = a0, b0, c0, d0

        def FF(a, b, c, d, x, s):
            return _rol((a + F(b, c, d) + x) & 0xFFFFFFFF, s)

        def GG(a, b, c, d, x, s):
            return _rol((a + G(b, c, d) + x + 0x5A827999) & 0xFFFFFFFF, s)

        def HH(a, b, c, d, x, s):
            return _rol((a + H(b, c, d) + x + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        # Round 1 (RFC 1320 reference order)
        A = FF(A, B, C, D, X[0], 3);   D = FF(D, A, B, C, X[1], 7)
        C = FF(C, D, A, B, X[2], 11);  B = FF(B, C, D, A, X[3], 15)
        A = FF(A, B, C, D, X[4], 3);   D = FF(D, A, B, C, X[5], 7)
        C = FF(C, D, A, B, X[6], 11);  B = FF(B, C, D, A, X[7], 15)
        A = FF(A, B, C, D, X[8], 3);   D = FF(D, A, B, C, X[9], 7)
        C = FF(C, D, A, B, X[10], 11); B = FF(B, C, D, A, X[11], 15)
        A = FF(A, B, C, D, X[12], 3);  D = FF(D, A, B, C, X[13], 7)
        C = FF(C, D, A, B, X[14], 11); B = FF(B, C, D, A, X[15], 15)

        # Round 2
        A = GG(A, B, C, D, X[0], 3);   D = GG(D, A, B, C, X[4], 5)
        C = GG(C, D, A, B, X[8], 9);   B = GG(B, C, D, A, X[12], 13)
        A = GG(A, B, C, D, X[1], 3);   D = GG(D, A, B, C, X[5], 5)
        C = GG(C, D, A, B, X[9], 9);   B = GG(B, C, D, A, X[13], 13)
        A = GG(A, B, C, D, X[2], 3);   D = GG(D, A, B, C, X[6], 5)
        C = GG(C, D, A, B, X[10], 9);  B = GG(B, C, D, A, X[14], 13)
        A = GG(A, B, C, D, X[3], 3);   D = GG(D, A, B, C, X[7], 5)
        C = GG(C, D, A, B, X[11], 9);  B = GG(B, C, D, A, X[15], 13)

        # Round 3
        A = HH(A, B, C, D, X[0], 3);   D = HH(D, A, B, C, X[8], 9)
        C = HH(C, D, A, B, X[4], 11);  B = HH(B, C, D, A, X[12], 15)
        A = HH(A, B, C, D, X[2], 3);   D = HH(D, A, B, C, X[10], 9)
        C = HH(C, D, A, B, X[6], 11);  B = HH(B, C, D, A, X[14], 15)
        A = HH(A, B, C, D, X[1], 3);   D = HH(D, A, B, C, X[9], 9)
        C = HH(C, D, A, B, X[5], 11);  B = HH(B, C, D, A, X[13], 15)
        A = HH(A, B, C, D, X[3], 3);   D = HH(D, A, B, C, X[11], 9)
        C = HH(C, D, A, B, X[7], 11);  B = HH(B, C, D, A, X[15], 15)

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def ntlm_hash(text: str) -> bytes:
    """NTLM = MD4 over UTF-16LE encoding of the string."""
    return md4(text.encode("utf-16-le"))


if __name__ == "__main__":
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert md4(b"message digest").hex() == "9e107d9d372bb6826bd81d3542a419d6"
    print("MD4 self-test OK (vectori RFC 1320)")
