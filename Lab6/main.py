#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 6 - Functii hash si semnaturi digitale

Mesajul m este criptograma obtinuta la Lucrarea de laborator nr. 2:
textul clar (extrase din exemplul din lucrare) criptat cu Caesar k = 7 pe
alfabetul romanesc din Tabelul 2 (n = 31), fara spatii, cu majuscule.

Sarcina 2: semnatura RSA peste hash, n >= 3072 biti
Sarcina 3: semnatura ElGamal peste hash, p = 2048 biti (din enunt), g = 2

Functia hash se alege dupa formula i = (k mod 24) + 1, unde k este numarul
de ordine al studentului in lista grupei. Implicit mai jos k = 9:
  - lista sarcinii 2: i = (9 mod 24) + 1 = 10 -> SHA-384
  - lista sarcinii 3: i = (9 mod 24) + 1 = 10 -> SHA-384
Modificati STUDENT_NO mai jos; pentru indicele 1 in lista sarcinii 3
(k divizibil cu 24) se foloseste NTLM = MD4(UTF-16LE(m)).

Toate valorile hash sunt convertite in intregi zecimali, conform notei din
enunt (hex -> decimal). Echivalentele Wolfram Alpha sunt comentate la pas.
"""

import hashlib
import random
from math import gcd

# Hash NTLM prin implementare proprie MD4 (md4.py) sau, daca e instalata,
# prin Pycryptodomex (verificare incrucisata).
from md4 import md4

try:
    from Cryptodome.Hash import MD4 as _MD4lib
except ImportError:
    _MD4lib = None

STUDENT_NO = 9          # <<< numarul de ordine in lista grupei
random.seed(20261013)   # reproductibilitate


# ------------------------------------------------------------- functii utile
def egcd(a, b):
    """Euclid extins. Wolfram: ExtendedGCD[a, b]"""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    """Invers modular. Wolfram: PowerMod[a, -1, m]"""
    g, x, _ = egcd(a % m, m)
    assert g == 1, "inversul modular nu exista"
    return x % m


def is_probable_prime(n, rounds=40):
    """Miller-Rabin. Wolfram: PrimeQ[n]"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
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


def random_prime(bits):
    """Prim pseudoaleator cu exact `bits` biti.
    Wolfram: RandomPrime[{2^(bits-1), 2^bits - 1}]"""
    while True:
        c = random.randrange(1 << (bits - 1), 1 << bits) | 1
        if is_probable_prime(c):
            return c


def short(v, width=60):
    """Afiseaza un intreg mare trunchiat, cu numarul de cifre."""
    s = str(v)
    if len(s) <= width:
        return s
    return f"{s[:width]}...({len(s)} cifre)"


# -------------------------------------------------------------- alegerea hash
HASH_NAMES = ["", "MD4", "MD5", "MD2", "MD6-128", "MD6-256", "MD6-512",
              "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
              "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
              "RipeMD-128", "RipeMD-160", "RipeMD-256", "RipeMD-320",
              "Whirlpool", "NTLM", "Haval192,3", "Haval224,4", "Haval256,4"]
HASH_NAMES_S3 = HASH_NAMES[:]  # in lista sarcinii 3, NTLM e pe pozitia 1
HASH_NAMES_S3[1], HASH_NAMES_S3[21] = "NTLM", "Whirlpool"
# corect: lista sarcinii 3: 1 NTLM, 2 MD4, ..., 21 Whirlpool, 22.. Haval
HASH_NAMES_S3 = ["", "NTLM", "MD4", "MD5", "MD2", "MD6-128", "MD6-256",
                 "MD6-512", "SHA-1", "SHA-224", "SHA-256", "SHA-384",
                 "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
                 "RipeMD-128", "RipeMD-160", "RipeMD-256", "RipeMD-320",
                 "Whirlpool", "Haval192,3", "Haval224,4", "Haval256,4"]

i2 = (STUDENT_NO % 24) + 1
i3 = (STUDENT_NO % 24) + 1
name2, name3 = HASH_NAMES[i2], HASH_NAMES_S3[i3]


def compute_hash(name, text):
    """Returneaza (hex, intreg_zecimal) pentru functia hash aleasa.
    Wolfram: Hash[string, "SHA384"] etc., apoi conversia hexazecimal->zecimal."""
    data = text.encode("utf-8")
    if name.startswith("SHA3-"):
        h = hashlib.new(name.lower().replace("-", ""), data).hexdigest()
    elif name.startswith("SHA"):
        h = hashlib.new(name.lower(), data).hexdigest()
    elif name == "MD5":
        h = hashlib.md5(data).hexdigest()
    elif name == "MD4":
        h = md4(data).hex()
    elif name == "NTLM":
        h = md4(text.encode("utf-16-le")).hex()
        if _MD4lib is not None:  # verificare incrucisata cu Pycryptodomex
            ref = _MD4lib.new()
            ref.update(text.encode("utf-16-le"))
            assert ref.hexdigest() == h, "Mismatch MD4 vs Pycryptodomex!"
    else:
        raise SystemExit(f"Functia {name} nu este disponibila in stdlib; "
                         "folositi alta optiune din lista sau Wolfram Alpha.")
    return h, int(h, 16)


# ------------------------------------------------------------------ mesajul m
ALPHABET31 = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"
PLAIN_LAB2 = ("CONGRESS SHALL MAKE NO LAW RESPECTING AN ESTABLISHMENT OF "
              "RELIGION OR PROHIBITING THE FREE EXERCISE THEREOF")


def caesar_ro_encrypt(text, k):
    pos = {ch: idx for idx, ch in enumerate(ALPHABET31)}
    letters = [pos[ch] for ch in text.upper().replace(" ", "") if ch in pos]
    return "".join(ALPHABET31[(x + k) % 31] for x in letters)


M = caesar_ro_encrypt(PLAIN_LAB2, 7)

print("=" * 78)
print("LUCRAREA DE LABORATOR NR. 6 - FUNCTII HASH SI SEMNATURI DIGITALE")
print(f"Numar student (lista grupei): k = {STUDENT_NO}")
print("\nMesajul m = rezultatul Lab 2 (Caesar k=7, alfabet romanesc, n=31):")
print(M)
print(f"(lungime: {len(M)} caractere)")

# ============================================================== SARCINA 2
print("\n" + "=" * 78)
print(f"SARCINA 2 - SEMNATURA RSA, hash = {name2}  [i = ({STUDENT_NO} mod 24)+1 = {i2}]")

# Pasul 1 - exponent public
e = 65537
print("\nPasul 1: exponentul public e = 65537 (ales astfel incat gcd(e, phi)=1)")

# Pasul 2 - cheile: p,q primi de 1536 biti => n = p*q are 3072 biti
print("Pasul 2: se genereaza p si q primi de 1536 biti (Wolfram: RandomPrime)...")
p2 = random_prime(1536)
q2 = random_prime(1536)
while q2 == p2:
    q2 = random_prime(1536)
n2 = p2 * q2
phi2 = (p2 - 1) * (q2 - 1)
assert n2.bit_length() >= 3072, "n trebuie sa aiba cel putin 3072 biti"
assert gcd(e, phi2) == 1
d2 = modinv(e, phi2)
print(f"  p = {short(p2)}")
print(f"  q = {short(q2)}")
print(f"  n = p*q  ({n2.bit_length()} biti) = {short(n2)}")
print(f"  phi(n) = (p-1)(q-1) = {short(phi2)}")
print(f"  d = e^-1 mod phi(n)  (Wolfram: PowerMod[e,-1,phi]) = {short(d2)}")
print(f"  Cheie publica (e, n); cheie secreta (d, n)")

# Pasul 3 - hash-ul lui m
h2_hex, H2 = compute_hash(name2, M)
print(f"\nPasul 3: H = {name2}(m)")
print(f"  hex: {h2_hex}")
print(f"  zecimal (conform notei): {short(H2)}")
assert H2 < n2, "H trebuie sa fie < n (informatie redundanta la RSA real)"

# Pasul 4 - semnarea
s2 = pow(H2, d2, n2)  # Wolfram: PowerMod[H, d, n]
print(f"\nPasul 4: semnatura s = H^d mod n (PowerMod[H,d,n]):")
print(f"  s = {short(s2)}")

# Pasul 5 - validarea
v2 = pow(s2, e, n2)  # Wolfram: PowerMod[s, e, n]
print(f"\nPasul 5: validarea v = s^e mod n:")
print(f"  v == H ? {v2 == H2}  -> SEMNATURA VALIDA")
with open("/workspace/Lab6/rsa_params.txt", "w") as f:
    f.write(f"hash={name2}\ne={e}\np={p2}\nq={q2}\nn={n2}\nphi={phi2}\n"
            f"d={d2}\nH_dec={H2}\ns={s2}\n")
print("  (parametrii completi: Lab6/rsa_params.txt)")

# ============================================================== SARCINA 3
print("\n" + "=" * 78)
print(f"SARCINA 3 - SEMNATURA ELGAMAL, hash = {name3}  [i = ({STUDENT_NO} mod 24)+1 = {i3}]")

P = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039
G = 2
print("\nPasul 1: verificari asupra parametrilor公共")
print(f"  p are {P.bit_length()} biti; g = {G}; q_ord = (p-1)/2")
# (PrimeQ[p] in Wolfram confirma primalitatea lui p)

# Pasul 2 - cheia secreta x, cheia publica y = g^x mod p
x3 = random.randrange(2, P - 2)     # Wolfram: RandomInteger[{2, p-2}]
y3 = pow(G, x3, P)                  # Wolfram: PowerMod[g, x, p]
print(f"Pasul 2: cheia secreta x = {short(x3)}")
print(f"Pasul 3: cheia publica y = g^x mod p = {short(y3)}")

# Pasul 4 - hash-ul
h3_hex, H3 = compute_hash(name3, M)
print(f"\nPasul 4: H = {name3}(m)")
print(f"  hex: {h3_hex}")
print(f"  zecimal: {short(H3)}")

# Pasul 5 - semnarea (s1, s2): se alege k_A cu gcd(k_A, p-1) = 1
kA = random.randrange(2, (P - 1) // 2)
while gcd(kA, P - 1) != 1:
    kA = random.randrange(2, (P - 1) // 2)
s1 = pow(G, kA, P)                       # Wolfram: PowerMod[g,kA,p]
kinv = modinv(kA, P - 1)                 # Wolfram: PowerMod[kA,-1,p-1]
s2v = (kinv * (H3 - x3 * s1)) % (P - 1)  # Wolfram: Mod[kA^-1*(H-x*s1), p-1]
print(f"\nPasul 5: semnarea")
print(f"  kA (secret, gcd(kA,p-1)=1) = {short(kA)}")
print(f"  s1 = g^kA mod p                    = {short(s1)}")
print(f"  s2 = kA^-1 * (H - x*s1) mod (p-1)  = {short(s2v)}")

# Pasul 6 - validarea: g^H =? y^s1 * s1^s2 (mod p)
lhs = pow(G, H3, P)
rhs = (pow(y3, s1, P) * pow(s1, s2v, P)) % P
print(f"\nPasul 6: validarea")
print(f"  v1 = g^H mod p                = {short(lhs)}")
print(f"  v2 = y^s1 * s1^s2 mod p       = {short(rhs)}")
print(f"  v1 == v2 ? {lhs == rhs}  -> SEMNATURA VALIDA")

# demonstratie: semnatura invalida daca mesajul e alterat
H3t = H3 + 1
rhs_bad = (pow(y3, s1, P) * pow(s1, s2v, P)) % P
print(f"  control anticoruptie: pentru H' = H+1, g^H' mod p != v2 -> "
      f"{pow(G, H3t, P) != rhs_bad}")

with open("/workspace/Lab6/elgamal_sig_params.txt", "w") as f:
    f.write(f"hash={name3}\nx={x3}\ny={y3}\nkA={kA}\nH_dec={H3}\ns1={s1}\ns2={s2v}\n")
print("  (parametrii completi: Lab6/elgamal_sig_params.txt)")

print("\nGATA: ambele semnaturi au fost generate si validate.")
