package main

import (
	"fmt"
	"os"
	"strings"
)

// ---------- Task 3.2: Vigenère cipher over the Romanian alphabet (n = 31) ----------
//
// Mathematical model (section 3.1, with n = 31 and codes 0..30 from Table 2):
//   encryption:  ci = (mi + ki) mod 31
//   decryption:  mi = (ci - ki + 31) mod 31
// The key is a word k2 of at least 7 Romanian letters; its letters are turned
// into shifts ki = code(k2[i mod len(k2)]) and repeated along the message.

const minKeywordLen = 7

// vigenereKeyCodes validates the keyword (only Romanian letters, length >= 7,
// converted to uppercase) and returns the numeric shifts ki (Table-2 codes).
func vigenereKeyCodes(keyword string) ([]int, bool, string) {
	upper, ok, msg := validateRomanianText(keyword)
	if !ok {
		return nil, false, msg
	}
	if len(upper) < minKeywordLen {
		return nil, false, fmt.Sprintf(
			"Cuvântul-cheie este prea scurt: are %d litere, dar lungimea minimă este %d caractere.",
			len(upper), minKeywordLen)
	}
	codes := make([]int, 0, len(upper))
	for _, r := range upper {
		c, _ := letterCode(r)
		codes = append(codes, c)
	}
	return codes, true, ""
}

// vigenere applies ci=(mi+ki) mod 31 (encrypt) or mi=(ci-ki+31) mod 31
// (decrypt) over the normalized uppercase, space-free text.
func vigenere(text []rune, key []int, encrypt bool) string {
	out := make([]rune, len(text))
	for i, r := range text {
		m, ok := letterCode(r)
		if !ok {
			out[i] = '?' // cannot happen: input was validated
			continue
		}
		k := key[i%len(key)]
		if encrypt {
			out[i] = codeLetter((m + k) % alphabetSize)
		} else {
			out[i] = codeLetter((m - k + alphabetSize) % alphabetSize)
		}
	}
	return string(out)
}

// runVigenere drives the interactive menu for Task 3.2: the user chooses the
// operation, enters the keyword (re-prompted while invalid) and the message
// (likewise), and receives the ciphertext / decrypted message.
func runVigenere(s *scanner) {
	fmt.Println("\n=== Sarcina 3.2: Cifrul Vigenere peste alfabetul romanesc (n=31) ===")
	operation := readOperation(s)

	var kw string
	var codes []int
	for {
		fmt.Print("Cuvantul-cheie k2 (minim 7 litere romanesti, A-Z/a-z, Ă Â Î Ș Ț): ")
		if !s.hasMore() {
			os.Exit(0)
		}
		kw = s.nextLine()
		var ok bool
		var msg string
		codes, ok, msg = vigenereKeyCodes(kw)
		if ok {
			break
		}
		fmt.Println("Cheie invalida:", msg)
	}
	keywordUpper := strings.ToUpper(cedillaReplacer.Replace(strings.Join(strings.Fields(kw), "")))

	var text []rune
	for {
		label := "Introduceti mesajul (text clar): "
		if operation == opDecrypt {
			label = "Introduceti criptograma: "
		}
		fmt.Print(label)
		if !s.hasMore() {
			os.Exit(0)
		}
		line := s.nextLine()
		norm, ok, msg := validateRomanianText(line)
		if !ok {
			fmt.Println(msg)
			continue
		}
		if len(norm) == 0 {
			fmt.Println("Textul nu poate fi gol.")
			continue
		}
		text = []rune(norm)
		break
	}

	result := vigenere(text, codes, operation == opEncrypt)

	fmt.Printf("\nText normalizat (majuscule, fara spatii, %d litere): %s\n", len(text), string(text))
	fmt.Printf("Cuvant-cheie prelucrat: %s (%d litere)\n", keywordUpper, len(codes))
	fmt.Printf("Deplasarile ki = codurile literelor cheii din Tabelul 2: %v\n", codes)
	if operation == opEncrypt {
		fmt.Println("Formula: ci = (mi + ki) mod 31")
		wrapText(result, 60)
		fmt.Printf("\nCriptograma: %s\n", result)
	} else {
		fmt.Println("Formula: mi = (ci - ki + 31) mod 31")
		wrapText(result, 60)
		fmt.Printf("\nMesajul decriptat: %s\n", result)
	}
}
