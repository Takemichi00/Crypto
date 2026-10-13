# Lucrare de laborator nr. 5.2 — PKI (OpenSSL) și semnătură digitală

**Cadrul didactic / Tema:** Public Key Infrastructure (PKI) and Digital Signature Algorithm
**Autor:** `<Nume Prenume>` **Grupa:** `<grupa>`

---

## 1. Obiective și condiții

Crearea unei infrastructuri cheie publice (PKI) interne folosind OpenSSL:
- generarea cheii private root și inițializarea unei Certificat Authority (CA);
- certificat auto-semnat pentru CA;
- emiterea și revocarea certificatelor/cheilor private pentru utilizatori;
- fiecare utilizator poate semna un fișier/document și verifica semnătura.

**Cerințe implementate:**
| Cerință | Cum a fost respectată |
|---|---|
| Algoritm RSA pentru cheile private | `openssl genrsa` peste tot (CA și utilizatori) |
| Valabilitatea cheilor/certificatelor utilizator: 365 zile, minim 2048 biți | `openssl ca -days 365`, dimensiunea verificată în script (`BITS >= 2048`) |
| Cheia privată CA: 4096 biți, certificat auto-semnat 10 ani (3650 zile) | `openssl genrsa -out ca.key.pem 4096`; `openssl req -x509 -days 3650` |

## 2. Structura proiectului

```
Lab5.2/
├── pki.sh          # scriptul Bash principal (CLI al PKI-ului)
├── REPORT.md       # acest raport
└── pki/            # directorul intern al autorității de certificare
    ├── openssl.cnf             # configurația CA (policy, extensii, rutine)
    ├── ca/
    │   ├── ca.key.pem          # cheia privată RSA-4096 a CA
    │   ├── ca.cert.pem         # certificatul auto-semnat al CA (3650 zile)
    │   ├── index.txt           # baza de date a entităților înregistrate
    │   ├── serial, crlnumber   # numerele de serie următoare
    │   └── crl/ca.crl.pem      # Certificate Revocation List
    └── users/<nume>/           # key, CSR, certificat, chain per utilizator
```

## 3. Utilizare

```bash
./pki.sh init                  # creează CA (RSA-4096, certificat auto-semnat 10 ani)
./pki.sh issue <user> [bits]   # înrolează un utilizator (RSA >=2048, certificat 365 zile)
./pki.sh sign  <user> <file>   # semnătura SHA-256 + RSA cu cheia privată a utilizatorului
./pki.sh verify <user> <file>  # verifică semnătura + lanțul de certificare + CRL
./pki.sh revoke <user>         # revocă certificatul și reîmprospătează CRL
./pki.sh crl                   # afișează CRL curent
./pki.sh status                # starea PKI
```

## 4. Fragmente de cod și comentarii

### 4.1 Inițializarea CA (RSA 4096, certificat auto-semnat 10 ani)

```bash
openssl genrsa -out "$CA_KEY" 4096
openssl req -config "$CONF" -key "$CA_KEY" -new -x509 \
    -days 3650 -sha256 -extensions v3_ca \
    -subj "/C=MD/ST=Chisinau/L=Chisinau/O=Internal PKI Lab/OU=Certification Authority/CN=Lab Root CA" \
    -out "$CA_CERT"
```
Se generează cheia root de 4096 biți și un certificat X.509 auto-semnat (Issuer == Subject), cu extensia `basicConstraints = critical, CA:true` și `keyUsage = digitalSignature, cRLSign, keyCertSign`, valabil 3650 de zile.

### 4.2 Emiterea certificatului unui utilizator (365 zile, min. 2048 biți)

```bash
openssl genrsa -out "$UDIR/$USER.key.pem" "$BITS"        # BITS >= 2048 (verificat în script)
openssl req -config "$CONF" -new -sha256 -key ... -subj "/CN=$USER" -out $USER.csr.pem
openssl ca -config "$CONF" -batch -extensions v3_user -days 365 \
    -notext -md sha256 -in "$UDIR/$USER.csr.pem" -out "$UDIR/$USER.cert.pem"
```
Utilizatorul își generează local cheia și CSR-ul; CA le semnează cu cheia sa (`openssl ca` actualizează `index.txt` și atribuie numărul de serie din `serial`). Extensiile `v3_user` marchează certificatul ca end-entity cu `keyUsage = digitalSignature`.

### 4.3 Semnarea unui document

```bash
openssl dgst -sha256 -sign "$UDIR/$USER.key.pem" -out "$FILE.sig.bin" "$FILE"
base64 "$FILE.sig.bin" > "$FILE.sig"
```
Se calculează hash-ul SHA-256 al fișierului și se criptează cu cheia **privată** a utilizatorului (semnătură RSA): `S = H(m)^d mod n`. Rezultatul binar e salvat și în bază 64 (format „detached signature”).

### 4.4 Validarea (semnătură + lanț + revocare)

```bash
openssl dgst -sha256 -verify <(openssl x509 -in cert.pem -pubkey -noout) \
    -signature "$FILE.sig.bin" "$FILE"
openssl verify -CAfile "$CA_CERT" -crl_check -CRLfile ca/crl/ca.crl.pem "$UDIR/$USER.cert.pem"
```
Verificarea are două niveluri: (1) integritatea+autenticitatea conținutului prin ridicarea semnăturii la puterea publică `e` și compararea cu hash-ul recomandat; (2) încrederea în certificatul emitentului — semnătura CA și consultarea CRL pentru revocare.

### 4.5 Revocarea și CRL

```bash
openssl ca -config "$CONF" -batch -revoke "users/$USER/$USER.cert.pem" -crl_reason keyCompromise
openssl ca -config "$CONF" -batch -gencrl -out ca/crl/ca.crl.pem
```
Întrarea din `index.txt` trece de la `V` (valid) la `R` (revocat) cu data și motivul revocării; CRL-ul reemis este semnat de CA și conține serialul certificatului revocat, ceea ce face ca verificările ulterioare să eșueze (`error 23: certificate revoked`).

## 5. Rezultate (transcrieri reale ale rulării)

### 5.1 Inițializarea CA
```
==> Generating CA private key (RSA 4096)
==> Creating self-signed CA certificate (valid 3650 days = 10 years)
==> CA initialized:
notBefore=Oct 13 07:35:32 2026 GMT
notAfter=Oct 10 07:35:32 2036 GMT
        Issuer: ... CN = Lab Root CA
        Subject: ... CN = Lab Root CA
                Public-Key: (4096 bit)
```
✅ 4096 biți, exact 10 ani, auto-semnat (Issuer = Subject).

### 5.2 Emiterea certificatului pentru alice (RSA 2048)
```
==> [alice] Issued certificate:
notBefore=Oct 13 07:35:41 2026 GMT
notAfter=Oct 13 07:35:41 2027 GMT          <- 365 zile
        Serial Number: 71E93A7CBF524B974FE9F379568E78DD4C06441B
        Issuer: ... CN = Lab Root CA        <- semnat de CA
        Subject: ... CN = alice
                Public-Key: (2048 bit)      ✅ minim 2048
```

### 5.3 Semnare și validare
```
==> [alice] Signing 'alice_doc.txt' (SHA-256 + RSA with the user's private key)
Signature written to alice_doc.txt.sig
==> [alice] Verifying signature of 'alice_doc.txt' against the CA chain
Verified OK
users/alice/alice.cert.pem: OK
RESULT: signature VALID and certificate trusted/not revoked
```

### 5.4 Detectarea modificării documentului (tamper test)
După adăugarea unei linii în fișierul semnat:
```
Verification failure
... bad signature ...
RESULT: verification FAILED (bad signature or revoked/untrusted certificate)
```

### 5.5 Revocare (bob, RSA 3072)
Semnătura lui bob validează inițial `RESULT: signature VALID...`. După `./pki.sh revoke bob`:
```
Revocation database (index.txt):
V  271013073541Z  ... CN=alice
R  271013073555Z  261013073555Z,keyCompromise  ... CN=bob
```
Validarea devine:
```
Verified OK                                  <- semnătura în sine e corectă
error 23 at 0 depth lookup: certificate revoked
RESULT: verification FAILED
```
Demonstrează separarea clară între autenticitatea criptografică a semnăturii și încrederea acordată prin certificat (revocabilă prin CRL).

## 6. Concluzii
- Un PKI funcțional complet necesită doar OpenSSL: cheie root RSA-4096, certificat auto-semnat (10 ani), bază de date `index.txt`, numere de serie, emitere CSR→certificat (365 zile, ≥2048 biți) și revocare prin CRL.
- Semnătura digitală RSA asigură autentificare, integritate și non-repudiere: orice modificare a documentului rupe verificarea, iar revocarea certificatului blochează validarea chiar dacă semnătura matematic rămâne corectă.
- Elementul de aport uman în PKI este încrederea în lanțul de certificare: verificatorul trebuie să dețină certificatul rădăcină al CA.

## 7. Cod sursă
Repository GitHub: `<link>` (directorul `Lab5.2/`: `pki.sh`, `pki/openssl.cnf`, artefacte generate).
