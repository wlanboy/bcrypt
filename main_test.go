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
	h1, err := HashTextOrFile("a", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := HashTextOrFile("b", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bcrypt.CompareHashAndPassword(h1, []byte("b")) == nil {
		t.Fatalf("hash of 'a' should not match 'b'")
	}
	if bcrypt.CompareHashAndPassword(h2, []byte("a")) == nil {
		t.Fatalf("hash of 'b' should not match 'a'")
	}
}

func TestTextTooLong(t *testing.T) {
	long := string(make([]byte, 73))
	_, err := HashTextOrFile(long, "")
	if err == nil {
		t.Fatalf("expected error for text exceeding 72 bytes, got nil")
	}
}
