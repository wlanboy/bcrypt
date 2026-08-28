package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	textPtr := flag.String("text", "", "Text to bcrypt hash.")
	filePtr := flag.String("file", "", "File to bcrypt hash (use - to read from stdin).")
	verifyPtr := flag.String("verify", "", "Bcrypt hash to verify against.")
	costPtr := flag.Int("cost", bcrypt.DefaultCost, fmt.Sprintf("Bcrypt cost factor (%d-%d).", bcrypt.MinCost, bcrypt.MaxCost))
	rawPtr := flag.Bool("raw", false, "Don't trim a trailing CR/LF from -text or stdin input.")
	flag.Parse()

	if *costPtr < bcrypt.MinCost || *costPtr > bcrypt.MaxCost {
		fmt.Fprintf(os.Stderr, "cost must be between %d and %d\n", bcrypt.MinCost, bcrypt.MaxCost)
		os.Exit(1)
	}

	text := *textPtr
	if text == "" && *filePtr == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		text = string(data)
		if !*rawPtr {
			text = strings.TrimRight(text, "\r\n")
		}
	}

	if text == "" && *filePtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *verifyPtr != "" {
		err := VerifyTextOrFile(text, *filePtr, *verifyPtr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verification failed:", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		return
	}

	hash, err := HashTextOrFile(text, *filePtr, *costPtr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(hash))
}

func readFileOrStdin(filePath string) ([]byte, error) {
	if filePath == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(filePath)
}

func HashTextOrFile(text string, filePath string, cost int) ([]byte, error) {
	if text != "" {
		if len([]byte(text)) > 72 {
			return nil, fmt.Errorf("text exceeds 72 bytes (bcrypt limit): %d bytes", len([]byte(text)))
		}
		return bcrypt.GenerateFromPassword([]byte(text), cost)
	}

	data, err := readFileOrStdin(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	sum := sha256.Sum256(data)
	return bcrypt.GenerateFromPassword(sum[:], cost)
}

func VerifyTextOrFile(text string, filePath string, hash string) error {
	if filePath != "" {
		data, err := readFileOrStdin(filePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
		sum := sha256.Sum256(data)
		return bcrypt.CompareHashAndPassword([]byte(hash), sum[:])
	}

	if len([]byte(text)) > 72 {
		return fmt.Errorf("text exceeds 72 bytes (bcrypt limit): %d bytes", len([]byte(text)))
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(text))
}
