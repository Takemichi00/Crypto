# Laboratory Work No. 1 — The Caesar Cipher

**Topic:** Caesar cipher and Caesar cipher with a keyword-based alphabet permutation over the Romanian alphabet
**Author:** *(student name)* — **Group:** *(group name)*
**Language:** Go (Golang) — source in `Lab1/` (`main.go`, `task1_1.go`, `task1_2.go`)

---

## 2. Short Theory

### 2.1 Classic Caesar cipher

Every plaintext letter is replaced by the letter found `k` positions further along an alphabet of size `n`. With `x` the position (0-based) of a plaintext letter and `y` the position of a ciphertext letter:

- **Encryption:** `c = e_k(x) = (x + k) mod n`
- **Decryption:** `m = d_k(y) = (y − k) mod n`
- **Key space:** `k ∈ {1, 2, …, n−1}` → for the Romanian alphabet (`n = 31`) there are **30 possible keys**. `k = 0` is excluded (identity).

Because negative results of `y − k` must be wrapped back into `0…n−1` (e.g. `(1 − 3) mod 31 = 29`), the modulo operation is implemented explicitly. The tiny key space makes the cipher trivially breakable by exhaustive search: trying all 30 shifts reveals exactly one readable text.

### 2.2 Caesar cipher with a permutation (two keys)

To enlarge the key space, the alphabet is first permuted using a **keyword** `k2`: write the distinct letters of the keyword (keeping only first occurrences), then append the remaining alphabet letters in natural order. The numeric code of a letter becomes its position in this **permuted alphabet**, and the classic shift `k1` is applied on top of it:

- **Encryption:** `c = π[(π⁻¹(x) + k1) mod n]`, where `π` is the permuted alphabet
- **Key space:** pair `(k1, k2)` → `n! × (n−1)` theoretically (`31! × 30 ≈ 8.22 × 10³⁵` for Romanian), practically driven by the number of distinct keywords. Exhaustive search becomes infeasible, but the cipher remains a **monoalphabetic substitution**, so it is still vulnerable to frequency analysis.

---

## 3. Implementation

### 3.1 Letter encoding (Table 2, `n = 31`)

The Romanian alphabet is stored as a single string constant; a letter's code is its **index** in this string — built-in encodings (ASCII/Unicode) are never used to compute the shift.

```go
const romanianAlphabet = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ" // A=0, Ă=1, Â=2, ..., Z=30
```
*Comment:* exact Table 2 ordering (31 letters); `letterCodes[letter] = index` maps each rune to its code, and `alphabet[code]` maps a code back to a letter.

### 3.2 Encryption / decryption (Task 1.1, `task1_1.go`)

```go
func caesarCipher(message []rune, key int, encrypt bool) string {
    alphabet := []rune(romanianAlphabet)
    letterCodes := make(map[rune]int, len(alphabet))
    for code, letter := range alphabet {
        letterCodes[letter] = code
    }
    result := make([]rune, 0, len(message))
    for _, letter := range message {
        code := letterCodes[letter]
        if encrypt {
            code = (code + key) % len(alphabet)
        } else {
            code = (code - key + len(alphabet)) % len(alphabet)
        }
        result = append(result, alphabet[code])
    }
    return string(result)
}
```
*Comment:* implements `e_k(x) = (x+k) mod 31` and `d_k(y) = (y−k) mod 31`. Adding `len(alphabet)` before the second modulo guarantees a non-negative result even when `y − k < 0` (Go's `%` can return negative remainders).

### 3.3 Building the permuted alphabet (Task 1.2, `task1_2.go`)

```go
func buildPermutedAlphabet(keyword []rune) []rune {
    result := make([]rune, 0, len([]rune(romanianAlphabet)))
    included := make(map[rune]bool)
    for _, letter := range append(keyword, []rune(romanianAlphabet)...) {
        if isRomanianLetter(letter) && !included[letter] {
            result = append(result, letter)
            included[letter] = true
        }
    }
    return result
}
```
*Comment:* keyword letters come first, then the rest of the alphabet in natural order; the `included` set keeps only the **first occurrence** of every letter, producing a permutation of all 31 letters. `keywordCaesarCipher` is identical to `caesarCipher` except that codes are taken from this permuted alphabet.

### 3.4 Input validation (`main.go`)

```go
func readShift() int {
    for {
        shift, err := strconv.Atoi(strings.TrimSpace(readLine("Enter numeric key k (1-30): ")))
        if err == nil && shift >= 1 && shift <= 30 {
            return shift
        }
        fmt.Println("Invalid key. The numeric key must be an integer from 1 to 30.")
    }
}

func normalize(value string) string {
    value = strings.ToUpper(value)
    value = strings.ReplaceAll(value, "Ş", "Ș")   // cedilla variants accepted
    value = strings.ReplaceAll(value, "Ţ", "Ț")
    return value
}
```
*Comment:* every input is requested inside a loop that re-prompts until valid, always printing the allowed range. Key 1 must be an integer in 1–30; the keyword may contain only Romanian letters and must be ≥ 7 characters after uppercasing; the message may contain only Romanian letters and spaces (spaces removed, invalid character reported by name). `normalize` uppercases the text and treats `Ş`/`Ţ` (cedilla) as `Ș`/`Ț` (comma below), per the implementation tip.

### 3.5 Program flow

The user chooses: cipher version (1 or 2) → operation (encrypt/decrypt) → numeric key → (for version 2) keyword, after which the program **displays the permuted alphabet** for manual checking → message/ciphertext → result.

---

## 4. Results

*(Screenshots of these exact terminal sessions should be inserted here.)*

### 4.1 Task 1.1 — encryption and decryption

```
Choose cipher (1-2): 1
Choose operation (1-2): 1
Enter numeric key k (1-30): 3
Enter message (spaces are removed): cifrul cezar
Ciphertext: FKITXOFHÂBT

Choose operation (1-2): 2   |  key 3, input FKITXOFHÂBT  ->  Plaintext: CIFRULCEZAR   ✓ round-trip
```
Note: the handout example (FLIUXOFHCDU) uses the 26-letter English alphabet; over the required Romanian alphabet (n = 31) `CIFRULCEZAR` with `k = 3` gives `FKITXOFHÂBT`, verified letter by letter against Table 2.

More plain-Caesar runs (all round-trip correctly):

| Plaintext | k | Ciphertext | Decrypt check |
|---|---|---|---|
| cifrul cezar | 3 | FKITXOFHÂBT | → CIFRULCEZAR ✓ |
| Cifrul Cezar | 4 | GLÎȚYPGIBCȚ | → CIFRULCEZAR ✓ |
| TEST | 15 | FSDF | → TEST ✓ |

### 4.2 Task 1.2 — keyword permutation

```
Choose cipher (1-2): 2
Choose operation (1-2): 1
Enter numeric key k (1-30): 3
Enter keyword (at least 7 Romanian letters): cryptography
Permuted alphabet: C R Y P T O G A H Ă Â B D E F I Î J K L M N Q S Ș Ț U V W X Z
Enter message (spaces are removed): CIFRUL CEZAR
Ciphertext: PKJTXQPÎYÂT          (decrypting with the same keys returns CIFRULCEZAR ✓)

Choose cipher (1-2): 2
Choose operation (1-2): 1
Enter numeric key k (1-30): 3
Enter keyword (at least 7 Romanian letters): romania
Permuted alphabet: R O M A N I Ă Â B C D E F G H Î J K L P Q S Ș T Ț U V W X Y Z
Enter message (spaces are removed): cifrul cezar
Ciphertext: FBÎAXSFHMĂA          (decrypt → CIFRULCEZAR ✓)

Keyword with diacritics:
Enter keyword: șoarece   k = 7   message: AAA BBB
Permuted alphabet: Ș O A R E C Ă Â B D F G H I Î J K L M N P Q S T Ț U V W X Y Z
Ciphertext: DDDJJJ               (decrypt → AAABBB ✓)
```

### 4.3 Invalid-input messages

```
Enter numeric key k (1-30): 0
Invalid key. The numeric key must be an integer from 1 to 30.
Enter numeric key k (1-30): 31
Invalid key. The numeric key must be an integer from 1 to 30.
Enter numeric key k (1-30): abc
Invalid key. The numeric key must be an integer from 1 to 30.

Enter message (spaces are removed): abc!
Invalid character '!'. Use only Romanian alphabet letters and spaces.

Enter keyword (at least 7 Romanian letters): abeci
Invalid keyword. It must contain at least 7 Romanian alphabet letters.

Enter keyword (at least 7 Romanian letters): chei!
Invalid keyword character '!'. Use only Romanian alphabet letters.
```
In every case the program re-prompts for the value instead of crashing. Lowercase input, cedilla variants `Ş`/`Ţ`, and embedded spaces are all accepted and normalized.

---

## 5. Conclusions

- The classic Caesar cipher over the Romanian alphabet has only **30 keys**; a brute-force attack trying all shifts instantly recovers the plaintext — it offers no real security.
- Permuting the alphabet with a keyword enlarges the key space enormously (theoretical maximum `31! × 30 ≈ 8.2 × 10³⁵`), making exhaustive search infeasible.
- However, both versions are **monoalphabetic substitutions**: each plaintext letter always maps to the same ciphertext letter, so letter frequencies survive encryption and the strengthened version remains vulnerable to frequency analysis. This illustrates why polyalphabetic ciphers (e.g. Vigenère) were historically the next step.
- Practically, I learned to implement modular arithmetic safely (handling negative remainders), to build bijective letter encodings independent of ASCII/Unicode, to generate keyword permutations with deduplication, and to design robust input validation loops.

## 6. Source Code

GitHub repository: **https://github.com/`<username>`/`<repo>`** *(update with your actual link)*

Structure:
```
Lab1/
├── go.mod        (module definition)
├── main.go       (menu, input validation, normalization)
├── task1_1.go    (Romanian alphabet constant + classic Caesar cipher)
└── task1_2.go    (permuted-alphabet builder + keyword Caesar cipher)
```
Build & run: `cd Lab1 && go build -o caesar . && ./caesar`
