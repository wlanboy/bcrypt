package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	textPtr := flag.String("text", "", "Text to bcrypt hash.")
	filePtr := flag.String("file", "", "File to bcrypt hash.")
	flag.Parse()

	if *textPtr == "" && *filePtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	hash, err := HashTextOrFile(*textPtr, *filePtr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(hash))
}

func HashTextOrFile(text string, filePath string) ([]byte, error) {
	if text != "" {
		return bcrypt.GenerateFromPassword([]byte(text), bcrypt.DefaultCost)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	sum := sha256.Sum256(data)
	return bcrypt.GenerateFromPassword(sum[:], bcrypt.DefaultCost)
}
