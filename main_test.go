package main

import (
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashText(t *testing.T) {
	hash, err := HashTextOrFile("hello", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bcrypt.CompareHashAndPassword(hash, []byte("hello")) != nil {
		t.Fatalf("hash does not match original text")
	}
}

func TestHashFile(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/test.txt"

	err := os.WriteFile(file, []byte("filecontent"), 0644)
	if err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	hash, err := HashTextOrFile("", file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Pre-hash for comparison
	sum := sha256.Sum256([]byte("filecontent"))
	if bcrypt.CompareHashAndPassword(hash, sum[:]) != nil {
		t.Fatalf("hash does not match SHA256(filecontent)")
	}
}

func TestMissingFile(t *testing.T) {
	_, err := HashTextOrFile("", "does-not-exist.txt")
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

func TestDifferentInputsProduceDifferentHashes(t *testing.T) {
	h1, _ := HashTextOrFile("a", "")
	h2, _ := HashTextOrFile("b", "")

	if string(h1) == string(h2) {
		t.Fatalf("different inputs should not produce identical hashes")
	}
}
