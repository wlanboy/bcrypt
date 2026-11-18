package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK    = 0 // success, password matches, rehash needed
	exitFail  = 1 // password mismatch, no rehash needed
	exitError = 2 // usage error, invalid hash, I/O error
)

const maxPasswordBytes = 72

const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

const usageHeader = `bcrypt hashes and verifies passwords and files.

Usage:
  bcrypt [flags]                      hash a password (prompt or stdin)
  bcrypt -verify HASH [flags]         check a password against a hash
  bcrypt -info HASH                   show version and cost of a hash
  bcrypt -needs-rehash HASH -cost N   check whether a hash uses a cost below N
  bcrypt -bench [-bench-target D]     find a cost that fits the target duration

Exit codes:
  0  success, password matches, rehash needed
  1  password does not match, no rehash needed
  2  usage error, invalid hash or I/O error

Flags:
`

type options struct {
	text        string
	file        string
	verify      string
	verifyFile  string
	verifyEnv   string
	cost        int
	raw         bool
	quiet       bool
	info        string
	needsRehash string
	bench       bool
	benchTarget time.Duration
	user        string
	version     bool

	set map[string]bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, code, ok := parseFlags(args, stderr)
	if !ok {
		return code
	}

	fail := func(err error) int {
		fmt.Fprintln(stderr, "bcrypt:", err)
		return exitError
	}

	if o.version {
		fmt.Fprintln(stdout, buildVersion())
		return exitOK
	}

	if err := validate(o); err != nil {
		return fail(err)
	}

	switch {
	case o.bench:
		return runBench(o, stdout, stderr)
	case o.set["info"]:
		return runInfo(o.info, stdout, stderr)
	case o.set["needs-rehash"]:
		return runNeedsRehash(o, stdout, stderr)
	}

	verifying := o.hashSources() > 0

	secret, err := readSecret(o, stdin, stderr, !verifying)
	if err != nil {
		return fail(err)
	}

	if verifying {
		hash, err := loadHash(o)
		if err != nil {
			return fail(err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), secret)
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			if !o.quiet {
				fmt.Fprintln(stderr, "verification failed: password does not match")
			}
			return exitFail
		}
		if err != nil {
			return fail(fmt.Errorf("verification failed: %w", err))
		}
		if !o.quiet {
			fmt.Fprintln(stdout, "OK")
		}
		return exitOK
	}

	hash, err := bcrypt.GenerateFromPassword(secret, o.cost)
	if err != nil {
		return fail(err)
	}
	if o.user != "" {
		fmt.Fprintf(stdout, "%s:%s\n", o.user, htpasswdHash(string(hash)))
		return exitOK
	}
	fmt.Fprintln(stdout, string(hash))
	return exitOK
}

func parseFlags(args []string, stderr io.Writer) (*options, int, bool) {
	o := &options{set: map[string]bool{}}
	fs := flag.NewFlagSet("bcrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageHeader)
		fs.PrintDefaults()
	}

	fs.StringVar(&o.text, "text", "", "Text to hash. Visible in ps and shell history, use only for tests.")
	fs.StringVar(&o.file, "file", "", "File to hash with SHA-256 prehash (use - to read from stdin).")
	fs.StringVar(&o.verify, "verify", "", "Bcrypt hash to verify against.")
	fs.StringVar(&o.verifyFile, "verify-file", "", "Read the hash to verify against from a file (with -user: htpasswd file).")
	fs.StringVar(&o.verifyEnv, "verify-env", "", "Read the hash to verify against from this environment variable.")
	fs.IntVar(&o.cost, "cost", bcrypt.DefaultCost, fmt.Sprintf("Bcrypt cost factor (%d-%d).", bcrypt.MinCost, bcrypt.MaxCost))
	fs.BoolVar(&o.raw, "raw", false, "Don't trim a trailing CR/LF from -text or stdin input.")
	fs.BoolVar(&o.quiet, "quiet", false, "No output for -verify, -needs-rehash and -bench details, only the exit code.")
	fs.StringVar(&o.info, "info", "", "Show version and cost of a bcrypt hash.")
	fs.StringVar(&o.needsRehash, "needs-rehash", "", "Exit 0 if the hash uses a cost below -cost, else 1.")
	fs.BoolVar(&o.bench, "bench", false, "Measure which cost fits -bench-target on this machine.")
	fs.DurationVar(&o.benchTarget, "bench-target", 250*time.Millisecond, "Target duration for -bench.")
	fs.StringVar(&o.user, "user", "", "Print htpasswd line user:hash; with -verify-file look up the user's hash.")
	fs.BoolVar(&o.version, "version", false, "Print version and exit.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK, false
		}
		return nil, exitError, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "bcrypt: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return nil, exitError, false
	}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	return o, exitOK, true
}

func (o *options) hashSources() int {
	n := 0
	for _, name := range []string{"verify", "verify-file", "verify-env"} {
		if o.set[name] {
			n++
		}
	}
	return n
}

func validate(o *options) error {
	if o.cost < bcrypt.MinCost || o.cost > bcrypt.MaxCost {
		return fmt.Errorf("cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	sources := o.hashSources()
	if sources > 1 {
		return errors.New("use only one of -verify, -verify-file and -verify-env")
	}

	modes := 0
	if sources > 0 {
		modes++
	}
	for _, name := range []string{"info", "needs-rehash", "bench"} {
		if o.set[name] {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("-verify, -info, -needs-rehash and -bench can't be combined")
	}

	if o.set["text"] && o.set["file"] {
		return errors.New("-text and -file can't be combined")
	}

	if o.set["user"] {
		if o.user == "" || strings.ContainsAny(o.user, ":\r\n") {
			return errors.New("-user must not be empty or contain ':' or line breaks")
		}
		if sources > 0 && !o.set["verify-file"] {
			return errors.New("-user with verification needs -verify-file")
		}
		if sources == 0 && o.set["file"] {
			return errors.New("-user (htpasswd output) can't be combined with -file")
		}
	}

	if o.bench && o.benchTarget <= 0 {
		return errors.New("-bench-target must be greater than 0")
	}
	return nil
}

// readSecret returns the bytes that get hashed or verified: the password itself
// or, with -file, the SHA-256 digest of the file content.
func readSecret(o *options, stdin io.Reader, stderr io.Writer, confirm bool) ([]byte, error) {
	if o.set["file"] {
		data, err := readFileOrStdin(o.file, stdin)
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
		sum := sha256.Sum256(data)
		return sum[:], nil
	}

	var password []byte
	switch fd, isTTY := terminalFd(stdin); {
	case o.set["text"]:
		password = []byte(o.text)
	case isTTY:
		p, err := promptPassword(fd, stderr, confirm)
		if err != nil {
			return nil, err
		}
		password = p
	default:
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		if !o.raw {
			data = bytes.TrimRight(data, "\r\n")
		}
		password = data
	}

	if len(password) == 0 {
		return nil, errors.New("empty password")
	}
	if len(password) > maxPasswordBytes {
		return nil, fmt.Errorf("password exceeds %d bytes (bcrypt limit): %d bytes", maxPasswordBytes, len(password))
	}
	return password, nil
}

func readFileOrStdin(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func terminalFd(r io.Reader) (int, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return 0, false
	}
	fd := int(f.Fd())
	return fd, term.IsTerminal(fd)
}

func promptPassword(fd int, stderr io.Writer, confirm bool) ([]byte, error) {
	fmt.Fprint(stderr, "Password: ")
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	if !confirm {
		return password, nil
	}

	fmt.Fprint(stderr, "Confirm password: ")
	again, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	if !bytes.Equal(password, again) {
		return nil, errors.New("passwords don't match")
	}
	return password, nil
}

func loadHash(o *options) (string, error) {
	switch {
	case o.set["verify-env"]:
		value, ok := os.LookupEnv(o.verifyEnv)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", o.verifyEnv)
		}
		return strings.TrimSpace(value), nil
	case o.set["verify-file"]:
		data, err := os.ReadFile(o.verifyFile)
		if err != nil {
			return "", fmt.Errorf("error reading hash file: %w", err)
		}
		if o.user != "" {
			return htpasswdLookup(string(data), o.user, o.verifyFile)
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return strings.TrimSpace(o.verify), nil
	}
}

func htpasswdLookup(content, user, source string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hash, ok := strings.Cut(line, ":")
		if ok && name == user {
			return hash, nil
		}
	}
	return "", fmt.Errorf("user %q not found in %s", user, source)
}

// htpasswdHash switches the $2a$ prefix to $2y$, which htpasswd writes and
// Apache expects. Go's implementation has none of the old $2a$ bugs, so the
// hash itself stays the same.
func htpasswdHash(hash string) string {
	if strings.HasPrefix(hash, "$2a$") {
		return "$2y$" + hash[4:]
	}
	return hash
}

type hashInfo struct {
	version string
	cost    int
}

func parseHash(hash string) (hashInfo, error) {
	hash = strings.TrimSpace(hash)
	if !strings.HasPrefix(hash, "$") {
		return hashInfo{}, errors.New("invalid bcrypt hash: missing '$' prefix")
	}
	ver, rest, _ := strings.Cut(hash[1:], "$")
	switch ver {
	case "2", "2a", "2b", "2x", "2y":
	default:
		return hashInfo{}, fmt.Errorf("invalid bcrypt hash: unknown version %q", ver)
	}
	costPart, payload, _ := strings.Cut(rest, "$")
	if len(costPart) != 2 {
		return hashInfo{}, errors.New("invalid bcrypt hash: cost must have two digits")
	}
	if len(payload) != 53 {
		return hashInfo{}, fmt.Errorf("invalid bcrypt hash: salt and hash must be 53 characters, got %d", len(payload))
	}
	if i := strings.IndexFunc(payload, func(r rune) bool { return !strings.ContainsRune(bcryptAlphabet, r) }); i >= 0 {
		return hashInfo{}, fmt.Errorf("invalid bcrypt hash: invalid character %q", payload[i])
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return hashInfo{}, fmt.Errorf("invalid bcrypt hash: %w", err)
	}
	return hashInfo{version: ver, cost: cost}, nil
}

func runInfo(hash string, stdout, stderr io.Writer) int {
	info, err := parseHash(hash)
	if err != nil {
		fmt.Fprintln(stderr, "bcrypt:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "version: %s\ncost:    %d\nrounds:  %d\n", info.version, info.cost, uint64(1)<<info.cost)
	return exitOK
}

func runNeedsRehash(o *options, stdout, stderr io.Writer) int {
	info, err := parseHash(o.needsRehash)
	if err != nil {
		fmt.Fprintln(stderr, "bcrypt:", err)
		return exitError
	}
	if info.cost < o.cost {
		if !o.quiet {
			fmt.Fprintf(stdout, "rehash needed: cost %d < %d\n", info.cost, o.cost)
		}
		return exitOK
	}
	if !o.quiet {
		fmt.Fprintf(stdout, "up to date: cost %d >= %d\n", info.cost, o.cost)
	}
	return exitFail
}

type benchResult struct {
	cost     int
	duration time.Duration
}

// benchmarkCost raises the cost until one hash takes longer than target and
// returns the highest cost that stayed within it (at least bcrypt.MinCost).
func benchmarkCost(target time.Duration, measure func(cost int) time.Duration) (int, []benchResult) {
	best := bcrypt.MinCost
	var results []benchResult
	for cost := bcrypt.MinCost; cost <= bcrypt.MaxCost; cost++ {
		d := measure(cost)
		results = append(results, benchResult{cost, d})
		if d > target {
			break
		}
		best = cost
	}
	return best, results
}

func measureCost(cost int) time.Duration {
	start := time.Now()
	_, _ = bcrypt.GenerateFromPassword([]byte("benchmark-password"), cost)
	return time.Since(start)
}

func runBench(o *options, stdout, stderr io.Writer) int {
	best, results := benchmarkCost(o.benchTarget, measureCost)
	if !o.quiet {
		fmt.Fprintf(stderr, "target: %v\n", o.benchTarget)
		for _, r := range results {
			fmt.Fprintf(stderr, "cost %2d: %10.1f ms\n", r.cost, float64(r.duration)/float64(time.Millisecond))
		}
		if best < bcrypt.DefaultCost {
			fmt.Fprintf(stderr, "note: cost %d is below the default of %d\n", best, bcrypt.DefaultCost)
		}
	}
	fmt.Fprintln(stdout, best)
	return exitOK
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
