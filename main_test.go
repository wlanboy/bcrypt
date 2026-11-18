package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String())
}

func mustHash(t *testing.T, password []byte) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	return string(hash)
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestHashText(t *testing.T) {
	code, out, _ := runCLI(t, "", "-text", "hello", "-cost", "4")
	if code != exitOK {
		t.Fatalf("exit code %d", code)
	}
	if bcrypt.CompareHashAndPassword([]byte(out), []byte("hello")) != nil {
		t.Fatalf("hash does not match original text")
	}
}

func TestHashStdinTrimsNewline(t *testing.T) {
	_, out, _ := runCLI(t, "hello\r\n", "-cost", "4")
	if bcrypt.CompareHashAndPassword([]byte(out), []byte("hello")) != nil {
		t.Fatalf("hash does not match trimmed stdin")
	}
}

func TestHashStdinRaw(t *testing.T) {
	_, out, _ := runCLI(t, "hello\n", "-cost", "4", "-raw")
	if bcrypt.CompareHashAndPassword([]byte(out), []byte("hello\n")) != nil {
		t.Fatalf("hash does not match raw stdin")
	}
}

func TestHashFile(t *testing.T) {
	path := writeFile(t, "filecontent")
	code, out, _ := runCLI(t, "", "-file", path, "-cost", "4")
	if code != exitOK {
		t.Fatalf("exit code %d", code)
	}
	sum := sha256.Sum256([]byte("filecontent"))
	if bcrypt.CompareHashAndPassword([]byte(out), sum[:]) != nil {
		t.Fatalf("hash does not match SHA256(filecontent)")
	}
}

func TestHashFileFromStdin(t *testing.T) {
	_, out, _ := runCLI(t, "filecontent", "-file", "-", "-cost", "4")
	sum := sha256.Sum256([]byte("filecontent"))
	if bcrypt.CompareHashAndPassword([]byte(out), sum[:]) != nil {
		t.Fatalf("hash does not match SHA256(filecontent)")
	}
}

func TestCustomCost(t *testing.T) {
	_, out, _ := runCLI(t, "", "-text", "hello", "-cost", "5")
	cost, err := bcrypt.Cost([]byte(out))
	if err != nil || cost != 5 {
		t.Fatalf("expected cost 5, got %d (%v)", cost, err)
	}
}

func TestInputErrors(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
		args  []string
	}{
		{"missing file", "", []string{"-file", "does-not-exist.txt"}},
		{"text too long", "", []string{"-text", strings.Repeat("a", 73)}},
		{"stdin too long", strings.Repeat("a", 73), nil},
		{"empty stdin", "\n", nil},
		{"empty text", "", []string{"-text", ""}},
		{"cost too low", "", []string{"-text", "a", "-cost", "3"}},
		{"cost too high", "", []string{"-text", "a", "-cost", "32"}},
		{"text and file", "", []string{"-text", "a", "-file", "x"}},
		{"two hash sources", "", []string{"-text", "a", "-verify", "x", "-verify-env", "X"}},
		{"verify and info", "", []string{"-text", "a", "-verify", "x", "-info", "x"}},
		{"bench and needs-rehash", "", []string{"-bench", "-needs-rehash", "x"}},
		{"user with colon", "", []string{"-text", "a", "-user", "a:b"}},
		{"user with file", "", []string{"-file", "x", "-user", "admin"}},
		{"user with verify", "", []string{"-text", "a", "-verify", "x", "-user", "admin"}},
		{"unknown flag", "", []string{"-nope"}},
		{"extra argument", "", []string{"-text", "a", "extra"}},
		{"bench target zero", "", []string{"-bench", "-bench-target", "0s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.stdin, tt.args...)
			if code != exitError {
				t.Fatalf("expected exit %d, got %d (stderr: %s)", exitError, code, stderr)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	hash := mustHash(t, []byte("hello"))

	code, out, _ := runCLI(t, "", "-text", "hello", "-verify", hash)
	if code != exitOK || out != "OK" {
		t.Fatalf("expected OK, got exit %d, out %q", code, out)
	}

	code, _, stderr := runCLI(t, "", "-text", "wrong", "-verify", hash)
	if code != exitFail || !strings.Contains(stderr, "does not match") {
		t.Fatalf("expected mismatch, got exit %d, stderr %q", code, stderr)
	}
}

func TestVerifyTrimsHash(t *testing.T) {
	hash := mustHash(t, []byte("hello"))
	code, _, _ := runCLI(t, "hello\n", "-verify", " "+hash+"\n")
	if code != exitOK {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	code, _, _ := runCLI(t, "", "-text", "hello", "-verify", "$2a$10$xxx")
	if code != exitError {
		t.Fatalf("expected exit %d, got %d", exitError, code)
	}
}

func TestVerifyFile(t *testing.T) {
	sum := sha256.Sum256([]byte("filecontent"))
	hash := mustHash(t, sum[:])
	path := writeFile(t, "filecontent")

	if code, _, _ := runCLI(t, "", "-file", path, "-verify", hash); code != exitOK {
		t.Fatalf("file verification failed with exit %d", code)
	}
	if code, _, _ := runCLI(t, "filecontent", "-file", "-", "-verify", hash); code != exitOK {
		t.Fatalf("stdin file verification failed with exit %d", code)
	}
}

func TestVerifyQuiet(t *testing.T) {
	hash := mustHash(t, []byte("hello"))

	code, out, stderr := runCLI(t, "hello", "-quiet", "-verify", hash)
	if code != exitOK || out != "" || stderr != "" {
		t.Fatalf("expected silent success, got exit %d, out %q, stderr %q", code, out, stderr)
	}

	code, out, stderr = runCLI(t, "wrong", "-quiet", "-verify", hash)
	if code != exitFail || out != "" || stderr != "" {
		t.Fatalf("expected silent mismatch, got exit %d, out %q, stderr %q", code, out, stderr)
	}
}

func TestVerifyFromHashFile(t *testing.T) {
	path := writeFile(t, mustHash(t, []byte("hello"))+"\n")
	if code, _, _ := runCLI(t, "hello", "-verify-file", path); code != exitOK {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if code, _, _ := runCLI(t, "hello", "-verify-file", "does-not-exist"); code != exitError {
		t.Fatalf("expected exit %d for missing hash file, got %d", exitError, code)
	}
}

func TestVerifyFromHtpasswd(t *testing.T) {
	content := "# comment\nalice:" + mustHash(t, []byte("a-pass")) + "\r\nbob:" + mustHash(t, []byte("b-pass")) + "\n"
	path := writeFile(t, content)

	if code, _, _ := runCLI(t, "b-pass", "-verify-file", path, "-user", "bob"); code != exitOK {
		t.Fatalf("expected bob to verify, got exit %d", code)
	}
	if code, _, _ := runCLI(t, "b-pass", "-verify-file", path, "-user", "alice"); code != exitFail {
		t.Fatalf("expected mismatch for alice, got exit %d", code)
	}
	if code, _, _ := runCLI(t, "b-pass", "-verify-file", path, "-user", "carol"); code != exitError {
		t.Fatalf("expected error for unknown user, got exit %d", code)
	}
}

func TestVerifyFromEnv(t *testing.T) {
	t.Setenv("BCRYPT_TEST_HASH", mustHash(t, []byte("hello")))
	if code, _, _ := runCLI(t, "hello", "-verify-env", "BCRYPT_TEST_HASH"); code != exitOK {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if code, _, _ := runCLI(t, "hello", "-verify-env", "BCRYPT_TEST_UNSET"); code != exitError {
		t.Fatalf("expected exit %d for unset variable, got %d", exitError, code)
	}
}

func TestHtpasswdOutput(t *testing.T) {
	code, out, _ := runCLI(t, "secret", "-user", "admin", "-cost", "4")
	if code != exitOK {
		t.Fatalf("exit code %d", code)
	}
	user, hash, ok := strings.Cut(out, ":")
	if !ok || user != "admin" || !strings.HasPrefix(hash, "$2y$04$") {
		t.Fatalf("unexpected htpasswd line %q", out)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("secret")) != nil {
		t.Fatalf("htpasswd hash does not verify")
	}
}

func TestInfo(t *testing.T) {
	hash := mustHash(t, []byte("hello"))
	code, out, _ := runCLI(t, "", "-info", hash)
	if code != exitOK {
		t.Fatalf("exit code %d", code)
	}
	for _, want := range []string{"version: 2a", "cost:    4", "rounds:  16"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q misses %q", out, want)
		}
	}
}

func TestParseHash(t *testing.T) {
	valid := mustHash(t, []byte("hello"))
	payload := valid[7:]

	if info, err := parseHash("$2y$12$" + payload); err != nil || info.version != "2y" || info.cost != 12 {
		t.Fatalf("expected 2y/12, got %+v (%v)", info, err)
	}

	invalid := []string{
		"",
		"hello",
		"$3a$10$" + payload,
		"$2a$1$" + payload,
		"$2a$10$" + payload[1:],
		"$2a$10$" + payload[1:] + "!",
		"$2a$99$" + payload,
	}
	for _, h := range invalid {
		if _, err := parseHash(h); err == nil {
			t.Errorf("expected error for %q", h)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	hash := mustHash(t, []byte("hello")) // cost 4

	code, out, _ := runCLI(t, "", "-needs-rehash", hash, "-cost", "10")
	if code != exitOK || !strings.Contains(out, "rehash needed") {
		t.Fatalf("expected rehash needed, got exit %d, out %q", code, out)
	}

	code, out, _ = runCLI(t, "", "-needs-rehash", hash, "-cost", "4")
	if code != exitFail || !strings.Contains(out, "up to date") {
		t.Fatalf("expected up to date, got exit %d, out %q", code, out)
	}

	code, out, _ = runCLI(t, "", "-needs-rehash", hash, "-cost", "10", "-quiet")
	if code != exitOK || out != "" {
		t.Fatalf("expected silent exit 0, got exit %d, out %q", code, out)
	}

	if code, _, _ := runCLI(t, "", "-needs-rehash", "garbage"); code != exitError {
		t.Fatalf("expected exit %d for invalid hash, got %d", exitError, code)
	}
}

func TestBenchmarkCost(t *testing.T) {
	// Fake timing: cost 4 takes 1ms, each step doubles.
	measure := func(cost int) time.Duration { return time.Millisecond << (cost - bcrypt.MinCost) }

	best, results := benchmarkCost(100*time.Millisecond, measure)
	if best != 10 { // 64ms fits, 128ms doesn't
		t.Fatalf("expected cost 10, got %d", best)
	}
	if len(results) != 8 || results[len(results)-1].cost != 11 {
		t.Fatalf("expected measurements for cost 4-11, got %v", results)
	}

	if best, _ := benchmarkCost(time.Microsecond, measure); best != bcrypt.MinCost {
		t.Fatalf("expected minimum cost when nothing fits, got %d", best)
	}
}

func TestBench(t *testing.T) {
	code, out, stderr := runCLI(t, "", "-bench", "-bench-target", "1ms")
	if code != exitOK || out == "" || !strings.Contains(stderr, "cost  4:") {
		t.Fatalf("unexpected bench result: exit %d, out %q, stderr %q", code, out, stderr)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "", "-version")
	if code != exitOK || out == "" {
		t.Fatalf("expected version output, got exit %d, out %q", code, out)
	}
}

func TestHelp(t *testing.T) {
	code, _, stderr := runCLI(t, "", "-h")
	if code != exitOK || !strings.Contains(stderr, "Exit codes:") {
		t.Fatalf("expected help text, got exit %d", code)
	}
}
