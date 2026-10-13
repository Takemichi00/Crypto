# Lucrare de laborator nr. 5 — Criptografia cu chei publice

**Numele și prenumele:** Nume Prenume
**Grupă:** Grupa ____
**Data:** ____.10.2026

---

## 1. Sarcina 1 — Studierea materialelor didactice (ELSE)

Materiale parcurse: *C4. Cifruri bloc*, *DES-FIPS-46 / FIPS-46-3*, *Theory of DES*,
*ASCII Character Set*, *DES eng/ro*. Idei reținute, relevante pentru această lucrare:

- Algoritmii simetrici (DES/AES) folosesc **o singură cheie secretă**, care trebuie
  transmisă securizat între părți — aici intervine criptografia cu chei publice.
- Reprezentarea caracterelor prin coduri ASCII (ex. `N`=0x4E=78, spațiu=0x20=32) este
  baza conversiei mesaj → număr întreg, cerută în sarcinile 2.1 și 2.2.
- Operațiile modulare (`a^b mod n`, inversul modular, testarea primimității) sunt
  nucleul algoritmulor RSA, ElGamal și Diffie-Hellman.

## 2. Baza matematică folosită

Toate calculele au fost făcute cu numere întregi mari (Python 3 `int`, echivalentul
`PowerMod`/`Mod` din Wolfram Alpha/Mathematica; comenzile exacte Wolfram sunt date la
fiecare pas) și **verificate încrucișat**: fiecare decriptare a recuperat exact textul
clar. Mesajul meu este:

```
m = "Nume Prenume"
```

Conversia conformă cu indicația (hexazecimal ASCII → zecimal):

| Caracter | Hex | Zecimal |
|---|---|---|
| N | 4E | 78 |
| u | 75 | 117 |
| m | 6D | 109 |
| e | 65 | 101 |
| (spațiu) | 20 | 32 |
| P | 50 | 80 |
| r | 72 | 114 |
| e | 65 | 101 |
| n | 6E | 110 |
| u | 75 | 117 |
| m | 6D | 109 |
| e | 65 | 101 |

Concatenând octeții: șirul hexazecimal al mesajului este
`4E 75 6D 65 20 50 72 65 6E 75 6D 65` = **0x4E756D65205072656E756D65**, adică în
zecimal **m = 24281791690356097997287550309**.

*(Wolfram: `FromIntegerDigits[IntegerDigits[62112100856578...]]` sau direct
`FromCharacterCode["Nume Prenume"]` transformat în număr; conversia hex→dec se poate
face și pe rapidtables.com.)*

## 3. Sarcina 2.1 — RSA (n ≥ 2048 biți)

### Pasul 1 — Generarea numerelor prime p și q (câte 1024 biți)

Wolfram: `p = RandomPrime[{2^1023, 2^1024}]`, `q = RandomPrime[{2^1023, 2^1024}]`.
Valorile obținute (complexe în fișierul `rsa_params.txt`; aici afișate prescurtat):

```
P = 1359137053150095639081057411483422233866...(309 cifre)...2285442951845196813411683817322685803559
Q = 1711582124783391327266227983330378625535...(309 cifre)...0324037750260714080057900308062912138143
```

Verificare primimitate: `PrimeQ[P]`, `PrimeQ[Q]` → True (test Miller–Rabin, 16 baze).

### Pasul 2 — Modulul n și funcția Euler φ(n)

```
n = P·Q = 2326274685302477764745456922119104033758...(617 cifre)...7958187151923901578935981853288769050937
```
**n are exact 2048 biți** (`BitLength[n] == 2048`), deci cerința „n de cel puțin
2048 biți” este îndeplinită.

```
φ(n) = (P−1)(Q−1) = 2326274685302477764745456922119104033758...(617 cifre)...5348706449817990685466397727903171109236
```

### Pasul 3 — Cheia publică e

Ales **e = 65537** (exponent Fermat, standard). Verificare `gcd(e, φ(n)) = 1`
(Wolfram: `GCD[65537, phi] == 1`) — True. Cheia publică: **(e, n) = (65537, n)**.

### Pasul 4 — Cheia privată d

d este inversul modular al lui e modulo φ(n): `d = ModInverse[e, φ(n)]`, adică
`e·d ≡ 1 (mod φ(n))`:

```
d = 2079083374921373119221747231324019722742...(617 cifre)...8458577336240431640444684897332383865317
```

Verificare: `Mod[e*d, phi] == 1` → True.

### Pasul 5 — Criptarea

```
c = m^e mod n = PowerMod[24281791690356097997287550309, 65537, n]
c = 1278217723498705789193091278016666228810...(616 cifre)...5704698129583060971535715938440485957198
```

### Pasul 6 — Decriptarea (verificare)

```
m' = c^d mod n = PowerMod[c, d, n] = 24281791690356097997287550309
```
Convertit înapoi prin hex→ASCII: `0x4E756D65205072656E756D65` → **„Nume Prenume”**. ✅
Decriptarea recuperează exact mesajul, deci cheia (e,d) este corectă.

## 4. Sarcina 2.2 — ElGamal (p = șirul de 2048 biți dat, g = 2)

Parametrii dați: **p** (2048 biți, safe prime: verificat că p și q=(p−1)/2 sunt ambele
prime), **g = 2**. Ordinul lui g este q, deci cheile se aleg din [2, q−2].

### Cheile

- Cheia secretă (aleatorie): `x = 1058707578676482349077767172619320207343...(617 cifre)...6755500072274409571587662559101661754918`
- Cheia publică: `y = g^x mod p = PowerMod[2, x, p]`
  `y = 1196571478100891249036754505880635491902...(617 cifre)...6087964222948251652759773671829850061641`

### Criptarea lui m = 24281791690356097997287550309

1. Număr aleatoriu per mesaj: `k = 9929963134746437928790608363248692331678...(616 cifre)...2507216659203504921025002379581129578259`
2. `c1 = g^k mod p = 4038075482942797547524249264596334323768...(616 cifre)...2664795420667677481942040278780383064676`
3. Masca shared: `s = y^k mod p = 2937240464181014655737379378172105501422...(617 cifre)...5536308422660553611325965646677641648216`
4. `c2 = m·s mod p = 2103331769596295328050712137470584174193...(617 cifre)...2328173257051511039663641782057853394412`

Criptograma este perechea **(c1, c2)**.

### Decriptarea

`s = c1^x mod p` (aceeași valoare ca mai sus — verificare a consistenței), apoi
`m = c2 · s⁻¹ mod p`, unde `s⁻¹ = PowerMod[s, p-2, p]` (teorema lui Fermat). Rezultat:
`m = 24281791690356097997287550309` → hex `4E756D65205072656E756D65` → **„Nume Prenume”** ✅

Observație: ElGamal e stohastic — aceeași m cu alt k dă altă criptogramă (c1≠, c2≠), dar
decriptarea e identică.

## 5. Sarcina 3 — Schimbul Diffie–Hellman (Alisa & Bob) + AES-256

Aceiași parametri: p (2048 biți), g = 2.

### Pasul 1 — Cheile secrete aleatoare (conform cerinței: a,b ∈ [2, p−2], practic [2,q−1])

```
a (Alisa) = 8847335690252589348656442103812372540743...(616 cifre)...4803088443225807998312777043788908708195
b (Bob)   = 7315390793978041088847128989523449860590...(616 cifre)...2690157700547698992696149714119234000308
```

### Pasul 2 — Valorile publice

```
A = g^a mod p = 2146867365526765702980633351828062888843...(617 cifre)...6084333339898147874216901599208715258097
B = g^b mod p = 2453997397528167267021320752585068281049...(617 cifre)...9310843360082378874340986162383429857770
```

Alisa îi trimite lui Bob valoarea A, Bob îi trimite Alisei valoarea B (canal nesecurizat).

### Pasul 3 — Secretul partajat

```
Alisa: K = B^a mod p
Bob:   K = A^b mod p
K = 1934830548850625784517881184518384380553...(617 cifre)...9749211679235624800760663027191568702017
```
Verificat `Mod[B^a,p] == Mod[A^b,p]` → True (ambele calcule coincid). ✅

### Pasul 4 — Derivarea cheii AES pe 256 de biți

Secretul K are 2048 biți; cheia AES-256 are nevoie de 256 biți, deci se derivă prin
hash: `key = SHA-256(K)` =

```
80464e9ed24ddfca0756faa99ea16935adb85025118b1d9f487e8f09e48b0951
```

### Pasul 5 — Criptarea unui bloc cu AES-256 (ECB, 1 bloc)

Cu cheia derivată mai sus, blocul `m = "Nume Prenume"` (padulat la 16 octeți cu 00):

```
intrare : 4e756d65205072656e756d6500000000
ieșire  : e1d31a52758201f8ac2643988390a1f4
```

Implementarea proprie de AES-256 (verificare independentă în Python, fără biblioteci)
este trecută peste **known-answer test-ul FIPS-197** (cheie 000102…1F, text
00112233…EEFF → 8ea2b7ca516745bfeafc49904b496089 ✅), deci rezultatul de mai sus este
AES-256 corect.

## 6. Concluzii

- **RSA** cu n de 2048 biți este infeasibil de spart prin factorizare; securitatea se
  bazează pe dificultatea `FactorInteger[n]`. Textul clar trebuie să fie < n, de aceea
  mesaje lungi se împart în blocuri (sau se combină cu un cifru simetric hibrid).
- **ElGamal** cu safe prime de 2048 biți oferă securitate bazată pe logaritmul discret;
  fiind stohastic, același mesaj produce criptograme diferite — proprietate importantă
  (semantic secure). Dezavantaj: criptograma are dublul dimensiunii mesajului.
- **Diffie–Hellman** permite două părți să stabilească o cheie secretă pe un canal
  public; secretul partajat nu poate fi calculat de un atacator (DDH). Din cei 2048
  biți ai lui K s-a derivat prin SHA-256 cheia de 256 de biți pentru AES — modelul
  hibrid real (DH/RSA = stabilire de cheie, AES = criptare în masă).
- Toate operațiile au fost verificate prin decriptare completă (mesajul inițial a fost
  recuperat de fiecare dată) și printr-o implementare independentă a AES-256 trecută
  peste testul oficial FIPS-197.

## 7. Cod sursă și fișiere

- `rsa_params.txt`, `elgamal_params.txt`, `dh_params.txt` — toate valorile complete
  (fără prescurtări) generate la acest laborator.
- `verify_dh_aes.py` — scriptul de verificare (generare chei, AES-256 propriu cu KAT
  FIPS-197, derivarea cheii din secretul DH).
- Link GitHub: ____________________ (de completat)

### Comenzi Wolfram Language equivalente (pentru reproducere)

```wl
p = RandomPrime[{2^1023, 2^1024}]; q = RandomPrime[{2^1023, 2^1024}];
n = p*q; phi = (p-1)(q-1); e = 65537; d = ModInverse[e, phi];
m = FromCharacterCode["Nume Prenume"]; (* interpretat ca număr big-endian *)
c = PowerMod[m, e, n]; PowerMod[c, d, n] === m
(* ElGamal/DH cu p-ul dat, g=2: *)
y = PowerMod[2, x, p]; c1 = PowerMod[2, k, p]; c2 = Mod[m*PowerMod[y,k,p], p];
m == Mod[c2*PowerMod[PowerMod[c1,x,p], p-2, p], p]
A = PowerMod[2,a,p]; B = PowerMod[2,b,p]; K = PowerMod[B,a,p] == PowerMod[A,b,p]
key = IntegerString[Hash[K, "SHA256"], 16, 64]
```
