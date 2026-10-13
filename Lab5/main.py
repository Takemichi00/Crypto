#!/usr/bin/env python3
"""Reproduce all Lab 5 computations (RSA, ElGamal, Diffie-Hellman + AES-256 KDF).

Usage:
    python3 main.py rsa
    python3 main.py elgamal
    python3 main.py dh
    python3 main.py all

Notes:
  * The task statement asks for Wolfram Alpha/Mathematica; the Wolfram-language
    equivalents are listed in REPORT.md. This script reproduces every numeric
    result with Python's arbitrary precision integers (same primitives as
    PowerMod/ModInverse/PrimeQ) so the report can be verified offline.
  * Message conversion follows the lab note: ASCII -> hex string -> decimal int.
"""
import hashlib
import random
import sys

P_2048 = int("""3231700607131100730015351347782516336248805713348907517458843413926
980683413621000279205636264016468545855635793533081692882902308057347
262527355474246124574102620252791657297286270630032526342821314576693
141422365422094111134862999165747826803423055308634905063555771221918
789033272956969612974385624174123623722519734640269185579776797682301
462539793305801522685873076119753243646747585546071504389684494036613
049769781285429595865959756705128385213278446852292550456827287911372
009893187395914337417583782600027803497319855206060753323412260325468
4088120031105907484281003994966956119696956248629032338072839127039""".replace("\n", ""))
G = 2
Q_ORDER = (P_2048 - 1) // 2          # P_2048 is a safe prime, ord(2) = Q_ORDER
MSG = "Nume Prenume"


def msg_to_int(msg: str) -> int:
    """ASCII -> hex -> decimal (as required by the lab note)."""
    hx = "".join(f"{ord(ch):02X}" for ch in msg)
    return int(hx, 16), hx


def short(x, n=40):
    s = str(x)
    if len(s) <= 2 * n:
        return s
    return f"{s[:n]}...({len(s)} cifre)...{s[-n:]}"


def is_prime(n, k=16):
    if n < 4:
        return n > 1
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 3
        if c % 3 and c % 5 and is_prime(c):
            return c


def rsa():
    m, hx = msg_to_int(MSG)
    print("== Sarcina 2.1 RSA ==")
    print(f"Mesaj: {MSG!r} -> hex {hx} -> zecimal m = {m}")
    p = gen_prime(1024)
    q = gen_prime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    assert n.bit_length() >= 2048
    c = pow(m, e, n)
    mr = pow(c, d, n)
    print(f"P (1024 biti) = {short(p)}")
    print(f"Q (1024 biti) = {short(q)}")
    print(f"N = P*Q ({n.bit_length()} biți) = {short(n)}")
    print(f"phi(N) = {short(phi)}")
    print(f"e = {e},  d = {short(d)}")
    print(f"Criptare:   c = m^e mod N = {short(c)}")
    print(f"Decriptare: m' = c^d mod N = {mr}  ->  {'OK' if mr == m else 'GRESIT'}")
    print(f"Verificare: (e*d) mod phi = {(e * d) % phi}")


def elgamal():
    m, hx = msg_to_int(MSG)
    print("== Sarcina 2.2 ElGamal (p 2048 biti, g=2) ==")
    print(f"P = {short(P_2048)}  ({P_2048.bit_length()} biți), prim: {is_prime(P_2048)}")
    print(f"q=(p-1)/2 prim (safe prime): {is_prime(Q_ORDER)}, ordinul lui g=2 este q: {pow(G, Q_ORDER, P_2048) == 1}")
    x = random.randrange(2, Q_ORDER - 2) + 2
    y = pow(G, x, P_2048)
    k = random.randrange(2, Q_ORDER - 2) + 2
    c1 = pow(G, k, P_2048)
    s = pow(y, k, P_2048)
    c2 = m * s % P_2048
    mr = c2 * pow(pow(c1, x, P_2048), -1, P_2048) % P_2048
    print(f"Cheie secreta x = {short(x)}")
    print(f"Cheie publica y = g^x mod p = {short(y)}")
    print(f"k (aleator per mesaj) = {short(k)}")
    print(f"c1 = g^k mod p = {short(c1)}")
    print(f"s  = y^k mod p = {short(s)}")
    print(f"c2 = m*s mod p = {short(c2)}")
    print(f"Criptograma = (c1, c2)")
    print(f"Decriptare: m = c2 * (c1^x)^-1 mod p = {mr} -> {'OK' if mr == m else 'GRESIT'}")


def dh():
    print("== Sarcina 3 Diffie-Hellman (Alisa & Bob) + AES-256 ==")
    a = random.randrange(2, Q_ORDER - 2) + 2
    b = random.randrange(2, Q_ORDER - 2) + 2
    A = pow(G, a, P_2048)
    B = pow(G, b, P_2048)
    Ka = pow(B, a, P_2048)
    Kb = pow(A, b, P_2048)
    assert Ka == Kb
    key = hashlib.sha256(Ka.to_bytes(256, "big")).digest()
    print(f"a (secret Alisa) = {short(a)}")
    print(f"b (secret Bob)   = {short(b)}")
    print(f"A = g^a mod p    = {short(A)}")
    print(f"B = g^b mod p    = {short(B)}")
    print(f"K (Alisa=B^a)    = {short(Ka)}")
    print(f"K (Bob=A^b)      = {short(Kb)}  -> identice: {Ka == Kb}")
    print(f"Cheie AES-256 = SHA-256(K) = {key.hex()}")
    print("Blocul 'Nume Prenume' padulat la 16 octeți se criptează cu această cheie")
    print("prin AES-256 (vezi verify_dh_aes.py pentru valorile exacte ale blocului).")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("rsa", "all"):
        rsa()
    if which in ("elgamal", "all"):
        elgamal()
    if which in ("dh", "all"):
        dh()
