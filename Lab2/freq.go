package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Alphabet of the Romanian language, ordered as in Table 2.1 (A Ă Â B ... Z).
const romanianLetters = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"

// Reference letter frequencies of the Romanian language, in percent
// (Table 2.1 of the laboratory work).
var romanianFreq = map[rune]float64{
	'A': 9.95, 'Ă': 4.06, 'Â': 0.91, 'B': 1.07, 'C': 5.28, 'D': 3.45,
	'E': 11.47, 'F': 1.18, 'G': 0.99, 'H': 0.47, 'I': 9.96, 'Î': 1.40,
	'J': 0.24, 'K': 0.11, 'L': 4.48, 'M': 3.10, 'N': 6.47, 'O': 4.07,
	'P': 3.18, 'Q': 0.00, 'R': 6.82, 'S': 4.40, 'Ș': 1.55, 'T': 6.04,
	'Ț': 1.00, 'U': 6.20, 'V': 1.23, 'W': 0.03, 'X': 0.11, 'Y': 0.07,
	'Z': 0.71,
}

// English alphabet and reference frequencies (Table 2.2), used by the
// example attack from section 2.3.
const englishLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

var englishFreq = map[rune]float64{
	'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
	'G': 2.01, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
	'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.09, 'R': 5.99,
	'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
	'Y': 1.97, 'Z': 0.07,
}

type langProfile struct {
	name    string
	letters string
	freq    map[rune]float64
}

func profileFor(name string) *langProfile {
	switch name {
	case "ro":
		return &langProfile{"Romanian", romanianLetters, romanianFreq}
	case "en":
		return &langProfile{"English", englishLetters, englishFreq}
	}
	return nil
}

// normalize prepares a text for analysis/decryption:
// cedilla variants are mapped to comma-below variants, everything is
// uppercased and only letters of the target alphabet are kept.
func normalize(text string, letters string) []rune {
	repl := strings.NewReplacer(
		"Ş", "Ș", "ş", "Ș", "ș", "Ș",
		"Ţ", "Ț", "ţ", "Ț", "ț", "Ț",
		"Ç", "C", "ç", "C",
	)
	upper := strings.ToUpper(repl.Replace(text))
	allowed := make(map[rune]bool, len(letters))
	for _, l := range letters {
		allowed[l] = true
	}
	out := make([]rune, 0, len(upper))
	for _, r := range upper {
		if allowed[r] {
			out = append(out, r)
		}
	}
	return out
}

// countFrequency returns the number of occurrences of every letter of the
// ciphertext that belongs to the analyzed alphabet.
func countFrequency(cipher []rune) map[rune]int {
	counts := make(map[rune]int)
	for _, r := range cipher {
		counts[r]++
	}
	return counts
}

type letterStat struct {
	letter rune
	count  int
	perc   float64
	ref    float64 // expected frequency of the plain letter currently assigned
}

// buildStats sorts the observed ciphertext letters by decreasing frequency
// (tables 2.3 / 2.4 of the lab).
func buildStats(counts map[rune]int, total int, assign map[rune]rune, p *langProfile) []letterStat {
	stats := make([]letterStat, 0, len(counts))
	for l, c := range counts {
		s := letterStat{letter: l, count: c, perc: 100 * float64(c) / float64(total)}
		if m, ok := assign[l]; ok {
			s.ref = p.freq[m]
		}
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].letter < stats[j].letter
	})
	return stats
}

func printFrequencyTable(stats []letterStat) {
	fmt.Println()
	fmt.Printf("%-4s %-6s %-9s %-12s\n", "Let", "Nr", "% text", "% asteptat")
	fmt.Println(strings.Repeat("-", 36))
	for _, s := range stats {
		fmt.Printf("%-4c %-6d %-9.2f %-12.2f\n", s.letter, s.count, s.perc, s.ref)
	}
}

// chiSquare measures how well the current substitution reproduces the
// reference frequency distribution of the language (lower is better).
// Only letters that have an assigned plaintext letter are counted, so the
// score decreases steadily as more of the key is recovered.
func chiSquare(counts map[rune]int, total int, assign map[rune]rune, p *langProfile) float64 {
	var chi float64
	assigned := 0.0
	for l, c := range counts {
		m, ok := assign[l]
		if !ok {
			continue
		}
		ref := p.freq[m]
		if ref <= 0 {
			continue
		}
		assigned += float64(c)
		expected := assignedTotal(total, assign, counts) * ref / 100.0
		d := float64(c) - expected
		chi += d * d / expected
	}
	return chi
}

// assignedTotal is the number of ciphertext letters covered by the current
// partial mapping; frequencies are renormalised over this subset.
func assignedTotal(total int, assign map[rune]rune, counts map[rune]int) float64 {
	s := 0.0
	for l, c := range counts {
		if _, ok := assign[l]; ok {
			s += float64(c)
		}
	}
	return s
}

// autoDecrypt maps the most frequent ciphertext letters onto the most
// frequent letters of the reference language (mechanical step of the attack).
func autoDecrypt(p *langProfile, stats []letterStat) map[rune]rune {
	order := []rune(p.letters)
	sort.Slice(order, func(i, j int) bool {
		if order[i] == 'Ș' {
			return true // keep S and Ș adjacent, as in Table 2.1
		}
		if order[j] == 'Ș' {
			return false
		}
		return p.freq[order[i]] > p.freq[order[j]]
	})
	assign := make(map[rune]rune)
	for i, s := range stats {
		if i < len(order) {
			assign[s.letter] = order[i]
		}
	}
	return assign
}

func applySubstitution(cipher []rune, assign map[rune]rune) string {
	out := make([]rune, len(cipher))
	for i, r := range cipher {
		if m, ok := assign[r]; ok {
			out[i] = m
		} else {
			out[i] = '?'
		}
	}
	return string(out)
}

// wordPattern implements the pattern-matching hint of section 2.2:
// '*' stands for any letter, e.g. "*i*" finds three-letter words whose
// middle letter is unknown. Returns the list of matching words with counts.
func wordPattern(pattern string, words []string) map[string]int {
	pat := []rune(strings.ToUpper(pattern))
	hits := make(map[string]int)
	for _, w := range words {
		rw := []rune(w)
		if len(rw) != len(pat) {
			continue
		}
		match := true
		for i, pr := range pat {
			if pr != '*' && pr != rw[i] {
				match = false
				break
			}
		}
		if match {
			hits[w]++
		}
	}
	return hits
}

// splitWords breaks the (letter-only) text into words using the space
// characters of the original input.
func splitWords(text string, letters string) []string {
	repl := strings.NewReplacer(
		"Ş", "Ș", "ş", "Ș", "ș", "Ș",
		"Ţ", "Ț", "ţ", "Ț", "ț", "Ț",
		"Ç", "C", "ç", "C",
	)
	upper := strings.ToUpper(repl.Replace(text))
	allowed := make(map[rune]bool, len(letters))
	for _, l := range letters {
		allowed[l] = true
	}
	var words []string
	var cur []rune
	for _, r := range upper {
		if allowed[r] {
			cur = append(cur, r)
		} else if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0]
		}
	}
	if len(cur) > 0 {
		words = append(words, string(cur))
	}
	return words
}

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

const englishSample = "GFS WMY OG LGDVS MF SFNKYHOSU ESLLMRS, PC WS BFGW POL " +
	"DMFRQMRS, PL OG CPFU M UPCCSKSFO HDMPFOSXO GC OIS LMES DMFRQMRS DGFR " +
	"SFGQRI OG CPDD GFS LISSO GK LG, MFU OISF WS NGQFO OIS GNNQKKSFNSL GC " +
	"SMNI DSOOSK. WS NMDD OIS EGLO CKSJQSFODY GNNQKKPFR DSOOSK OIS 'CPKLO', " +
	"OIS FSXO EGLO GNNQKKPFR DSOOSK OIS 'LSNGFU' OIS CGDDGWPFR EGLO " +
	"GNNQKKPFR DSOOSK OIS 'OIPKU', MFU LG GF, QFOPD WS MNNGQFO CGK MDD OIS " +
	"UPCCSKSFO DSOOSKL PF OIS HDMPFOSXO LMEHDS. OISF WS DGGB MO OIS NPHISK " +
	"OSXO WS WMFO OG LGDVS MFU WS MDLG NDMLLPCY POL LYEAGDL. WS CPFU OIS " +
	"EGLO GNNQKKPFR LYEAGD MFU NIMFRS PO OG OIS CGKE GC OIS 'CPKLO' DSOOSK " +
	"GC OIS HDMPFOSXO LMEHDS, OIS FSXO EGLO NGEEGF LYEAGD PL NIMGRSU OG OIS " +
	"CGKE GC OIS 'LSNGFU' DSOOSK, MFU OIS CGDDGWPFR EGLO NGEEGF LYEAGD PL " +
	"NIMGRSU OG OIS CGKE GC OIS 'OIPKU' DSOOSK, MFU LG GF, QFOPD WS " +
	"MNNGQFOT CGK MDD LYEAGDL GC OIS NKYHOGRKME WS WMFT OG LGDVS."

const romanianSample = "TEXTUL ACESTA ESTE UN EXEMPLU PENTRU ANALIZA FRECVENTEI " +
	"LITERELOR LIMBII ROMANE IN CADRUL LUCRARII DE LABORATOR NUMARUL DOI " +
	"CRIPTANALIZA CIFRURILOR MONOALFABETICE ATACUL BAZAT PE FRECVENTA " +
	"APARITIEI LITERELOR ESTE CEL MAI EFFICIENT IMPOTRIVA SUBSTITUTIILOR " +
	"SIMPLE FIIND CA FIECARE LITERA A TEXTULUI CLAR ESTE INLOCUITA " +
	"INTOTDEAUNA CU ACEASI LITERA DIN TEXTUL CIFRAT ASTFEL PROPORTIILE " +
	"FRECVENTELOR SE PASTREAZA SI POT FI FOLOSITE PENTRU RECUPERAREA CHEII"

// caesarShift applies a Caesar shift over the given alphabet ordering
// (same math as Task 1.1/1.2 of Lab 1), used to produce example ciphertexts.
func caesarShift(text string, letters string, k int, decrypt bool) string {
	pos := make(map[rune]int)
	for i, l := range []rune(letters) {
		pos[l] = i
	}
	n := len(pos)
	out := make([]rune, 0, len(text))
	for _, r := range normalize(text, letters) {
		i := pos[r]
		j := (i + k) % n
		if decrypt {
			j = (i - k%n + n) % n
		}
		out = append(out, []rune(letters)[j])
	}
	return string(out)
}

func main() {
	p := profileFor("ro")
	reader := newScanner(os.Stdin)
	fmt.Println("Lucrarea de laborator nr. 2 - Criptanaliza cifrurilor monoalfabetice")
	fmt.Println("Analiza frecventei literelor si atacul prin analiza frecventei")
	for {
		fmt.Println("\nOptiuni:")
		fmt.Println("  1 = Cifrare Caesar (exemplu de criptograma, alfabet romanesc)")
		fmt.Println("  2 = Criptanaliza prin analiza frecventei (text scris de dvs.)")
		fmt.Println("  3 = Demonstration attack on the English ciphertext (section 2.3)")
		fmt.Println("  0 = Iesire")
		fmt.Print("Alegeti optiunea: ")
		switch strings.TrimSpace(reader.nextLine()) {
		case "0":
			return
		case "1":
			k := readInt(reader, "Cheia numerica k (1-30): ", 1, 30)
			msg := reader.nextLineRequired("Introduceti textul clar: ")
			ct := caesarShift(msg, p.letters, k, false)
			fmt.Printf("Textul cifrat (Caesar, k=%d): %s\n", k, ct)
			fmt.Println("(folositi optiunea 2 pentru a sparge acest text fara a sti cheia)")
		case "2":
			runAttack(reader, p)
		case "3":
			runAttack(reader, profileFor("en"))
		default:
			fmt.Println("Optiune invalida. Alegeti 0, 1, 2 sau 3.")
		}
	}
}

func runAttack(reader *scanner, p *langProfile) {
	fmt.Print("Introduceti textul cifrat (sau 'exemplu' pentru textul demonstrativ): ")
	raw := reader.nextLine()
	var words []string
	if strings.EqualFold(strings.TrimSpace(raw), "exemplu") || strings.EqualFold(strings.TrimSpace(raw), "example") {
		if p.name == "English" {
			raw = englishSample
		} else {
			raw = romanianSample
		}
		fmt.Println("(folosim textul demonstrativ incarcate)")
	}
	words = splitWords(raw, p.letters)
	cipher := normalize(raw, p.letters)
	if len(cipher) == 0 {
		fmt.Println("Nu s-a gasit nici o litera valida in text.")
		return
	}
	counts := countFrequency(cipher)
	stats := buildStats(counts, len(cipher), nil, p)
	fmt.Printf("\nLungimea textului analizat: %d litere\n", len(cipher))
	printFrequencyTable(stats)

	assign := autoDecrypt(p, stats)
	fmt.Println("\nSubstitutie automata (cea mai freq. litera din criptograma -> cea mai freq. litera a limbii):")
	sortedAssign := make([]rune, 0, len(assign))
	for c := range assign {
		sortedAssign = append(sortedAssign, c)
	}
	sort.Slice(sortedAssign, func(i, j int) bool { return sortedAssign[i] < sortedAssign[j] })
	var b strings.Builder
	for _, c := range sortedAssign {
		fmt.Fprintf(&b, "%c->%c ", c, assign[c])
	}
	wrapText(b.String(), 60)
	fmt.Println("\nText parțial decriptat:")
	wrapText(applySubstitution(cipher, assign), 60)
	fmt.Printf("\nChi-square al substitutiei automate: %.1f (cu cat e mai mic, cu atat se apropie mai mult de limba tinta)\n", chiSquare(counts, len(cipher), assign, p))

	// manual refinement loop
	fmt.Println("\nEtapa interactiva: affinati corespondentele (traseuri de personalitate ale literelor,")
	fmt.Println("ex. cuvinte de 2-3 litere, digrafe/trigrafe frecvente). Comenzi:")
	fmt.Println("   <CIFRATA>=<CLARA>   ex: S=E     (asigneaza / schimba o corespondenta)")
	fmt.Println("   del <CIFRATA>       sterge o asignare")
	fmt.Println("   tab                 reafiseaza tabelul de frecvente")
	fmt.Println("   text                reafiseaza decriptarea curenta")
	fmt.Println("   gata                incheie analiza")
	for {
		fmt.Print("\n> ")
		cmd := strings.TrimSpace(reader.nextLine())
		if cmd == "" {
			continue
		}
		if strings.EqualFold(cmd, "gata") {
			break
		}
		switch {
		case strings.EqualFold(cmd, "tab"):
			printFrequencyTable(buildStats(counts, len(cipher), assign, p))
		case strings.EqualFold(cmd, "text"):
			wrapText(applySubstitution(cipher, assign), 60)
		case strings.HasPrefix(strings.ToLower(cmd), "del "):
			target := normalize(strings.TrimSpace(cmd[4:]), p.letters)
			if len(target) == 1 {
				delete(assign, target[0])
				fmt.Println("Asignare stearsa.")
			} else {
				fmt.Println("Specificati o singura litera cifrata.")
			}
		case strings.Contains(cmd, "="):
			parts := strings.SplitN(cmd, "=", 2)
			ct := normalize(parts[0], p.letters)
			pt := normalize(parts[1], p.letters)
			if len(ct) != 1 || len(pt) != 1 {
				fmt.Println("Format asteptat: LITERACIFRATA=LITERACLARA (cate o litera de fiecare parte).")
				continue
			}
			c, m := ct[0], pt[0]
			// keep the mapping bijective: remove m if assigned elsewhere
			for oc, om := range assign {
				if om == m && oc != c {
					delete(assign, oc)
					fmt.Printf("(litera %c eliberata din vechea corespondenta %c)\n", m, oc)
				}
			}
			assign[c] = m
			wrapText(applySubstitution(cipher, assign), 60)
			wordPatternDemo(words, assign)
			fmt.Printf("\nChi-square: %.1f\n", chiSquare(counts, len(cipher), assign, p))
		default:
			fmt.Println("Comanda necunoscuta.")
		}
	}
}

// wordPatternDemo shows the pattern search of section 2.2 on the current
// partial decryption: words are decrypted letter by letter, unknown letters
// are shown as '*'.
func wordPatternDemo(words []string, assign map[rune]rune) {
	decrypted := make([]string, 0, len(words))
	for _, w := range words {
		rw := []rune(w)
		out := make([]rune, len(rw))
		for i, r := range rw {
			if m, ok := assign[r]; ok {
				out[i] = m
			} else {
				out[i] = '*'
			}
		}
		decrypted = append(decrypted, string(out))
	}
	freq := make(map[string]int)
	for _, w := range decrypted {
		freq[w]++
	}
	list := make([]string, 0, len(freq))
	for w := range freq {
		list = append(list, w)
	}
	sort.Slice(list, func(i, j int) bool {
		if freq[list[i]] != freq[list[j]] {
			return freq[list[i]] > freq[list[j]]
		}
		return list[i] < list[j]
	})
	fmt.Println("\nCuvinte cu cel putin un caracter necunoscut (*) - cele mai frecvente:")
	shown := 0
	for _, w := range list {
		if strings.Contains(w, "*") {
			fmt.Printf("%-15s x%d\n", w, freq[w])
			shown++
			if shown >= 12 {
				break
			}
		}
	}
}

// ---------- small input helpers ----------

type scanner struct{ r *bufio.Reader }

func newScanner(f *os.File) *scanner { return &scanner{r: bufio.NewReader(f)} }

func (s *scanner) nextLine() string {
	line, err := s.r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
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

func readInt(s *scanner, prompt string, min, max int) int {
	for {
		line := strings.TrimSpace(s.nextLine())
		v, err := strconv.Atoi(line)
		if err == nil && v >= min && v <= max {
			return v
		}
		fmt.Printf("Valoare invalida. Introduceti un intreg intre %d si %d.\n", min, max)
	}
}
