package main

import (
	"fmt"
	"os"
	"strings"
)

type operation int

const (
	opEncrypt operation = iota
	opDecrypt
)

// readOperation lets the user choose between encryption and decryption,
// re-prompting on invalid input.
func readOperation(s *scanner) operation {
	for {
		fmt.Print("Optiunea (1 = criptare, 2 = decriptare): ")
		if !s.hasMore() {
			os.Exit(0)
		}
		switch strings.TrimSpace(s.nextLine()) {
		case "1":
			return opEncrypt
		case "2":
			return opDecrypt
		default:
			fmt.Println("Optiune invalida. Alegeti 1 sau 2.")
		}
	}
}

func main() {
	reader := newScanner(os.Stdin)

	fmt.Println("Lucrarea de laborator nr. 3 - Cifruri polialfabetice")
	fmt.Println("Sarcina 3.1: Playfair (alfabet romanesc, matrice 6x6)")
	fmt.Println("Sarcina 3.2: Vigenere (alfabet romanesc, n = 31, coduri 0..30)")
	for {
		fmt.Println("\nOptiuni:")
		fmt.Println("  1 = Sarcina 3.1: Cifrul Playfair")
		fmt.Println("  2 = Sarcina 3.2: Cifrul Vigenere")
		fmt.Println("  0 = Iesire")
		fmt.Print("Alegeti optiunea: ")
		if !reader.hasMore() {
			return
		}
		switch strings.TrimSpace(reader.nextLine()) {
		case "0":
			fmt.Println("La revedere!")
			return
		case "1":
			runPlayfair(reader)
		case "2":
			runVigenere(reader)
		default:
			fmt.Println("Optiune invalida. Alegeti 0, 1 sau 2.")
		}
	}
}
