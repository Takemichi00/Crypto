package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// romanianAlphabet is the 31-letter Romanian alphabet encoded exactly as in
// Table 2 of Lab 1: A=0, Ă=1, Â=2, B=3, ..., Z=30. The position of a letter
// in this string IS its numeric code; built-in encodings (ASCII/Unicode) are
// never used to compute shifts.
const romanianAlphabet = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"

const alphabetSize = 31 // n = 31

// cedillaReplacer maps the cedilla keyboard variants Ş/Ţ (and their lowercase
// forms, handled after ToUpper) onto the official comma-below letters Ș/Ț, so
// that text typed on different keyboards is accepted (implementation tip of
// Lab 1, kept here for consistency).
var cedillaReplacer = strings.NewReplacer(
	"Ş", "Ș", "ş", "Ș", "ș", "Ș",
	"Ţ", "Ț", "ţ", "Ț", "ț", "Ț",
)

// letterCode returns the Table-2 code of an uppercase Romanian letter and
// whether the rune is a valid letter of the alphabet.
func letterCode(r rune) (int, bool) {
	for i, l := range []rune(romanianAlphabet) {
		if l == r {
			return i, true
		}
	}
	return -1, false
}

// codeLetter converts a numeric code (0..30) back into its letter.
func codeLetter(code int) rune {
	alphabet := []rune(romanianAlphabet)
	return alphabet[code]
}

// validateRomanianText checks that every non-space character of s is a letter
// of the Romanian alphabet (upper or lower case, cedilla variants accepted).
// It returns the normalized text: uppercase, spaces removed. On the first
// invalid character it returns ok=false together with a clear message naming
// the rejected character and the allowed ranges.
func validateRomanianText(s string) (string, bool, string) {
	s = cedillaReplacer.Replace(s)
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' {
			continue // spaces are allowed and removed
		}
		u := r
		if u >= 'a' && u <= 'z' {
			u -= 32 // lowercase a-z -> uppercase A-Z
		}
		switch r {
		case 'ă':
			u = 'Ă'
		case 'â':
			u = 'Â'
		case 'î':
			u = 'Î'
		}
		if _, ok := letterCode(u); !ok {
			return "", false, fmt.Sprintf(
				"Caracter invalid: '%c'. Sunt permise doar literele alfabetului românesc: "+
					"A–Z, a–z, Ă/ă, Â/â, Î/î, Ș/ş/Ş, Ț/ţ/Ţ (și spații, care se elimină).", r)
		}
		b.WriteRune(u)
	}
	return b.String(), true, ""
}

// normalizeUpper uppercases a (already validated) Romanian text and removes
// spaces, as required before encryption.
func normalizeUpper(s string) []rune {
	res, _, _ := validateRomanianText(s)
	return []rune(res)
}

// ---------- small input helpers (same style as Lab 1 / Lab 2) ----------

type scanner struct{ r *bufio.Reader }

func newScanner(f *os.File) *scanner { return &scanner{r: bufio.NewReader(f)} }

func (s *scanner) nextLine() string {
	line, err := s.r.ReadString('\n')
	if err != nil && line == "" {
		return "" // EOF: let the caller's validation loop reject it and exit if needed
	}
	return strings.TrimRight(line, "\r\n")
}

// hasMore reports whether the input stream still has data (used to stop
// interactive loops cleanly at end-of-input).
func (s *scanner) hasMore() bool {
	_, err := s.r.Peek(1)
	return err == nil
}

func (s *scanner) nextLineRequired(prompt string) string {
	for {
		fmt.Print(prompt)
		line := s.nextLine()
		if strings.TrimSpace(line) != "" {
			return line
		}
		fmt.Println("Textul nu poate fi gol.")
	}
}

// readKey reads the numeric key k1, accepting only integers from min to max
// inclusive, re-prompting with a clear message otherwise.
func readKey(s *scanner, prompt string, min, max int) int {
	for {
		fmt.Print(prompt)
		if !s.hasMore() {
			os.Exit(0)
		}
		line := strings.TrimSpace(s.nextLine())
		v, err := parseInt(line)
		if err == nil && v >= min && v <= max {
			return v
		}
		fmt.Printf("Cheie invalida (%q). Cheia trebuie sa fie un intreg intre %d si %d.\n", line, min, max)
	}
}

func parseInt(s string) (int, error) {
	neg := false
	t := s
	if strings.HasPrefix(t, "-") {
		neg = true
		t = t[1:]
	}
	if t == "" {
		return 0, fmt.Errorf("gol")
	}
	v := 0
	for _, r := range t {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("nu e intreg")
		}
		v = v*10 + int(r-'0')
	}
	if neg {
		v = -v
	}
	return v, nil
}

// wrapText prints a long string in fixed-width lines (for readability).
func wrapText(s string, width int) {
	runes := []rune(s)
	for len(runes) > width {
		fmt.Println(string(runes[:width]))
		runes = runes[width:]
	}
	if len(runes) > 0 {
		fmt.Println(string(runes))
	}
}
