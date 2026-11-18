# bcrypt
bcrypt command line tool

# build
* go mod download
* go build
* go test

# hash text
* ./bcrypt -text "hello world"

Use `-text` only for tests. Arguments show up in `ps` and in the shell history, so pass real passwords via stdin.

# hash file
* ./bcrypt -file .gitignore

# stdin
* echo "hello world" | ./bcrypt
* cat myfile | ./bcrypt -file -

# verify
* ./bcrypt -text "hello world" -verify "$HASH"
* ./bcrypt -file .gitignore -verify "$HASH"
* echo "hello world" | ./bcrypt -verify "$HASH"
* cat myfile | ./bcrypt -file - -verify "$HASH"

# custom cost (default: 10, range: 4-31)
* ./bcrypt -text "hello world" -cost 12

# raw mode (keep a trailing CR/LF instead of trimming it)
* echo "hello world" | ./bcrypt -raw

# flags
| Flag | Description |
|------|-------------|
| `-text` | Text to bcrypt hash |
| `-file` | File to bcrypt hash (SHA-256 prehash); use `-` to read from stdin |
| `-verify` | Bcrypt hash to verify against |
| `-cost` | Cost factor, default 10, range 4-31 |
| `-raw` | Don't trim a trailing CR/LF from `-text` or stdin input |

# docker hub
* https://hub.docker.com/repository/docker/wlanboy/bcrypt

# usage with docker
* alias bcrypt="docker run -i --rm wlanboy/bcrypt"
* read -rs PW; printf '%s' "$PW" | bcrypt; unset PW
* cat myfile | bcrypt -file -

Don't pass secrets with `-text` here either: container arguments also show up in `docker ps --no-trunc` and `docker inspect`.

# multi-arch build (amd64 + arm64)
* docker buildx create --use
* docker buildx build --platform linux/amd64,linux/arm64 -t wlanboy/bcrypt:latest .
