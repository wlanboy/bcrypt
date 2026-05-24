# bcrypt
bcrypt command line tool

# build
* go mod download
* go build
* go test

# hash text
* ./bcrypt -text "hello world"

# hash file
* ./bcrypt -file .gitignore

# stdin
* echo "hello world" | ./bcrypt

# verify
* ./bcrypt -text "hello world" -verify "$HASH"
* ./bcrypt -file .gitignore -verify "$HASH"
* echo "hello world" | ./bcrypt -verify "$HASH"

# custom cost (default: 10, range: 4-31)
* ./bcrypt -text "hello world" -cost 12

# flags
| Flag | Description |
|------|-------------|
| `-text` | Text to bcrypt hash |
| `-file` | File to bcrypt hash (SHA-256 prehash) |
| `-verify` | Bcrypt hash to verify against |
| `-cost` | Cost factor, default 10, range 4-31 |

# docker hub
* https://hub.docker.com/repository/docker/wlanboy/bcrypt

# usage with docker
* alias bcrypt="docker run -i --rm wlanboy/bcrypt"
* bcrypt -text "hello world"
* echo "hello world" | bcrypt

# multi-arch build (amd64 + arm64)
* docker buildx create --use
* docker buildx build --platform linux/amd64,linux/arm64 -t wlanboy/bcrypt:latest -f Dockerfile.multiarch .
