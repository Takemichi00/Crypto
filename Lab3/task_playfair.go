package main

import (
	"fmt"
	"os"
	"strings"
)

// ---------- Task 3.1: Playfair cipher over the Romanian alphabet (n = 31) ----------
//
// The 31-letter alphabet does not fit a 5x5 matrix, so we use a 6x6 matrix
// (36 cells) as foreseen by the lab text ("matricea poate fi alta, spre
// exemplu 6x5, 5x6, ... în care pot fi plasate toate literele alfabetului").
// After the 31 letters, the 5 free cells are filled with the digits 0-4, so
// that every cell of the ciphertext is still an alphanumeric character.
//
// Rules implemented (section 3.2.3):
//   - plaintext prepared uppercase, without spaces/punctuation, in digraphs;
//   - J is replaced by I (here also for the key/matrix, standard Playfair);
//   - a filler letter X is inserted between equal letters of the same pair
//     (X may only appear alone at the very end, where it is padded to XX);
//   - if the number of letters is odd, a final X is added;
//   - matrix built from the de-duplicated keyword, then the remaining
//     alphabet letters in order, then the filler digits;
//   - rectangle rule: each letter is replaced by the letter on its own row
//     and the column of its partner;
//   - same row: replace by the NEXT letter of the row (wrapping);
//     same column: replace by the letter one ROW DOWN (wrapping);
//   - decryption reverses the last two rules (previous letter / row up).
// Note: like classic Playfair, this cipher is an involution on fixed points:
// a pair lying on the diagonal of the rectangle encrypts to itself, which is
// normal behaviour of the algorithm.

const playfairFiller = 'X' // inserted between doubled letters and as final pad

type playfairMatrix struct {
	grid   [6][6]rune
	pos    map[rune][2]int // letter -> {row, col}
	digits string          // fillers used for the free cells
}

// buildPlayfairMatrix validates the keyword (>= 7 Romanian letters), removes
// repeated letters (keeping the first occurrence), replaces J by I and fills
// the 6x6 grid row by row: keyword letters, then the rest of the alphabet in
// Table-2 order, then the digits 0..4 in the remaining cells.
func buildPlayfairMatrix(keyword string) (*playfairMatrix, bool, string) {
	upper, ok, msg := validateRomanianText(keyword)
	if !ok {
		return nil, false, msg
	}
	if len(upper) < minKeywordLen {
		return nil, false, fmt.Sprintf(
			"Cheia este prea scurtă: are %d litere, dar lungimea minimă este %d caractere.",
			len(upper), minKeywordLen)
	}
	m := &playfairMatrix{pos: make(map[rune][2]int), digits: "01234"}
	used := map[rune]bool{}
	var seq []rune
	add := func(r rune) {
		if r == 'J' {
			r = 'I' // J is mapped onto I everywhere
		}
		if !used[r] {
			used[r] = true
			seq = append(seq, r)
		}
	}
	for _, r := range upper {
		add(r)
	}
	for _, r := range romanianAlphabet {
		add(r)
	}
	for _, r := range m.digits {
		add(r)
	}
	i := 0
	for row := 0; row < 6; row++ {
		for col := 0; col < 6; col++ {
			m.grid[row][col] = seq[i]
			m.pos[seq[i]] = [2]int{row, col}
			i++
		}
	}
	return m, true, ""
}

func (m *playfairMatrix) print() {
	fmt.Println("Matricea de criptare 6x6:")
	for row := 0; row < 6; row++ {
		fmt.Print("  ")
		for col := 0; col < 6; col++ {
			fmt.Printf("%c ", m.grid[row][col])
		}
		fmt.Println()
	}
}

// preparePlayfairText converts the message into the list of digraphs ready
// for encryption: uppercase, no spaces, J->I, X inserted between doubles,
// final X added when the count is odd.
func preparePlayfairText(text []rune) []rune {
	var out []rune
	for _, r := range text {
		if r == 'J' {
			r = 'I'
		}
		out = append(out, r)
	}
	prepared := make([]rune, 0, len(out)+1)
	i := 0
	for i < len(out) {
		a := out[i]
		b := rune(0)
		if i+1 < len(out) {
			b = out[i+1]
		}
		if b != 0 && a == b {
			// doubled letter inside the same pair: insert the filler X
			prepared = append(prepared, a, playfairFiller)
			i += 1 // the second copy starts the next pair
		} else {
			prepared = append(prepared, a)
			if b != 0 {
				prepared = append(prepared, b)
			}
			i += 2
		}
	}
	if len(prepared)%2 == 1 {
		prepared = append(prepared, playfairFiller) // odd length -> add X
	}
	return prepared
}

// playfairPair encrypts/decrypts one digraph according to the three rules.
func (m *playfairMatrix) playfairPair(a, b rune, decrypt bool) (rune, rune) {
	p1, p2 := m.pos[a], m.pos[b]
	if p1[0] != p2[0] && p1[1] != p2[1] {
		// rectangle: swap columns (identical for encryption and decryption)
		return m.grid[p1[0]][p2[1]], m.grid[p2[0]][p1[1]]
	}
	step := 1
	if decrypt {
		step = -1
	}
	if p1[0] == p2[0] { // same row: shift along the row
		c1 := (p1[1] + step + 6) % 6
		c2 := (p2[1] + step + 6) % 6
		return m.grid[p1[0]][c1], m.grid[p2[0]][c2]
	}
	// same column: shift along the column
	r1 := (p1[0] + step + 6) % 6
	r2 := (p2[0] + step + 6) % 6
	return m.grid[r1][p1[1]], m.grid[r2][p2[1]]
}

// splitDigraphs groups a slice of runes into printable pairs "AB CD ...".
func splitDigraphs(t []rune) string {
	var b strings.Builder
	for i := 0; i < len(t); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(t[i])
		if i+1 < len(t) {
			b.WriteRune(t[i+1])
		}
	}
	return b.String()
}

func playfairRun(m *playfairMatrix, prepared []rune, decrypt bool) string {
	out := make([]rune, 0, len(prepared))
	for i := 0; i < len(prepared); i += 2 {
		x, y := m.playfairPair(prepared[i], prepared[i+1], decrypt)
		out = append(out, x, y)
	}
	return string(out)
}

// runPlayfair drives the interactive menu for Task 3.1.
func runPlayfair(s *scanner) {
	fmt.Println("\n=== Sarcina 3.1: Cifrul Playfair peste alfabetul romanesc (matrice 6x6) ===")
	operation := readOperation(s)

	var kw string
	var matrix *playfairMatrix
	for {
		fmt.Print("Cheia k (minim 7 litere romanesti, A-Z/a-z, Ă Â Î Ș Ț): ")
		if !s.hasMore() {
			os.Exit(0)
		}
		kw = s.nextLine()
		var ok bool
		var msg string
		matrix, ok, msg = buildPlayfairMatrix(kw)
		if ok {
			break
		}
		fmt.Println("Cheie invalida:", msg)
	}
	matrix.print()

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

	if operation == opEncrypt {
		prepared := preparePlayfairText(text)
		fmt.Printf("\nPerechi pregatite pentru criptare (%d litere): %s\n", len(prepared), splitDigraphs(prepared))
		ct := playfairRun(matrix, prepared, false)
		wrapText(ct, 60)
		fmt.Printf("\nCriptograma: %s\n", ct)
	} else {
		if len(text)%2 == 1 {
			fmt.Println("Atentie: criptograma are numar impar de litere; se adauga un X final pentru impartirea in perechi.")
			text = append(text, playfairFiller)
		}
		fmt.Printf("\nPerechi din criptograma: %s\n", splitDigraphs(text))
		pt := playfairRun(matrix, text, true)
		wrapText(pt, 60)
		fmt.Printf("\nMesaj decriptat (spațiile dintre cuvinte se restaulesază manual):\n%s\n", pt)
	}
}
