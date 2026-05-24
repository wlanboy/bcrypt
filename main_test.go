package main

import (
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashText(t *testing.T) {
	hash, err := HashTextOrFile("hello", "", bcrypt.DefaultCost)
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

	hash, err := HashTextOrFile("", file, bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sum := sha256.Sum256([]byte("filecontent"))
	if bcrypt.CompareHashAndPassword(hash, sum[:]) != nil {
		t.Fatalf("hash does not match SHA256(filecontent)")
	}
}

func TestMissingFile(t *testing.T) {
	_, err := HashTextOrFile("", "does-not-exist.txt", bcrypt.DefaultCost)
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

func TestDifferentInputsProduceDifferentHashes(t *testing.T) {
	h1, err := HashTextOrFile("a", "", bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := HashTextOrFile("b", "", bcrypt.DefaultCost)
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
	_, err := HashTextOrFile(long, "", bcrypt.DefaultCost)
	if err == nil {
		t.Fatalf("expected error for text exceeding 72 bytes, got nil")
	}
}

func TestCustomCost(t *testing.T) {
	hash, err := HashTextOrFile("hello", "", 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("failed to read cost from hash: %v", err)
	}
	if cost != 4 {
		t.Fatalf("expected cost 4, got %d", cost)
	}
}

func TestVerifyText(t *testing.T) {
	hash, err := HashTextOrFile("hello", "", bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := VerifyTextOrFile("hello", "", string(hash)); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifyTextWrongPassword(t *testing.T) {
	hash, err := HashTextOrFile("hello", "", bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if VerifyTextOrFile("wrong", "", string(hash)) == nil {
		t.Fatalf("expected verification failure for wrong password")
	}
}

func TestVerifyFile(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/test.txt"

	err := os.WriteFile(file, []byte("filecontent"), 0644)
	if err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	hash, err := HashTextOrFile("", file, bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := VerifyTextOrFile("", file, string(hash)); err != nil {
		t.Fatalf("file verification failed: %v", err)
	}
}

func TestVerifyFileMissing(t *testing.T) {
	if VerifyTextOrFile("", "does-not-exist.txt", "$2a$10$xxx") == nil {
		t.Fatalf("expected error for missing file")
	}
}
