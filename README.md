# bcrypt
bcrypt command line tool, build with golang. 

# build
* go mod download
* go build -ldflags "-X main.version=$(git describe --tags --always)"
* go test

# hash a password
* ./bcrypt

In a terminal the tool asks for the password twice without echoing it. With piped input it reads the password from stdin:

* echo "hello world" | ./bcrypt
* ./bcrypt -text "hello world"

Use `-text` only for tests. Arguments show up in `ps` and in the shell history.

# hash a file
The tool prehashes the file content with SHA-256, so files of any size work.

* ./bcrypt -file .gitignore
* cat myfile | ./bcrypt -file -

# verify
Without piped input the tool asks for the password.

* ./bcrypt -verify "$HASH"
* echo "hello world" | ./bcrypt -verify "$HASH"
* ./bcrypt -file .gitignore -verify "$HASH"
* cat myfile | ./bcrypt -file - -verify "$HASH"

The hash can also come from a file or an environment variable:

* ./bcrypt -verify-file hash.txt
* ./bcrypt -verify-env PASSWORD_HASH

For scripts, `-quiet` suppresses all output except errors:

* if ./bcrypt -quiet -verify-env PASSWORD_HASH < pw.txt; then echo valid; fi

# htpasswd
`-user` prints a line for `.htpasswd` files (nginx, Apache, Traefik), with the `$2y$` prefix htpasswd uses:

* ./bcrypt -user admin >> .htpasswd

Together with `-verify-file`, `-user` looks up the user's hash in an htpasswd file:

* ./bcrypt -verify-file .htpasswd -user admin

# inspect a hash
* ./bcrypt -info "$HASH"

```
version: 2a
cost:    10
rounds:  1024
```

# check if a hash needs a rehash
Exits with 0 if the hash uses a cost below `-cost`, with 1 if not:

* ./bcrypt -needs-rehash "$HASH" -cost 12

# find a cost for this machine
`-bench` raises the cost until one hash takes longer than `-bench-target` (default 250ms) and prints the highest cost that stayed within it. The timings go to stderr, the cost to stdout:

* ./bcrypt -bench
* ./bcrypt -bench -bench-target 500ms

# custom cost (default: 10, range: 4-31)
* ./bcrypt -cost 12

# raw mode (keep a trailing CR/LF instead of trimming it)
* echo "hello world" | ./bcrypt -raw

# flags
| Flag | Description |
|------|-------------|
| `-text` | Text to hash, for tests only |
| `-file` | File to hash (SHA-256 prehash); use `-` to read from stdin |
| `-verify` | Bcrypt hash to verify against |
| `-verify-file` | Read the hash from a file; with `-user` from an htpasswd file |
| `-verify-env` | Read the hash from an environment variable |
| `-cost` | Cost factor, default 10, range 4-31 |
| `-raw` | Don't trim a trailing CR/LF from `-text` or stdin input |
| `-quiet` | No output for `-verify`, `-needs-rehash` and the `-bench` timings |
| `-user` | Print `user:hash` for htpasswd; with `-verify-file` select the user |
| `-info` | Show version, cost and rounds of a hash |
| `-needs-rehash` | Exit 0 if the hash's cost is below `-cost`, else 1 |
| `-bench` | Find the highest cost within `-bench-target` |
| `-bench-target` | Target duration for `-bench`, default 250ms |
| `-version` | Print the version |

# exit codes
| Code | Meaning |
|------|---------|
| 0 | Success, password matches, rehash needed |
| 1 | Password does not match, no rehash needed |
| 2 | Usage error, invalid hash or I/O error |

# docker hub
* https://hub.docker.com/repository/docker/wlanboy/bcrypt

# usage with docker
* alias bcrypt="docker run -it --rm wlanboy/bcrypt"
* bcrypt
* cat myfile | docker run -i --rm wlanboy/bcrypt -file -

Use `-it` for the password prompt and `-i` without `-t` for piped input. Don't pass secrets with `-text` here either: container arguments also show up in `docker ps --no-trunc` and `docker inspect`.

# multi-arch build (amd64 + arm64)
* docker buildx create --use
* docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v2.0.0 -t wlanboy/bcrypt:latest .
