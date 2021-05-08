# bcrypt
bcrypt command line tool

# build
* go get -d -v
* go clean
* go build

# run
* go run main.go

# debug
* go get -u github.com/go-delve/delve/cmd/dlv
* dlv debug ./goservice

# hash text
* bcrypt -text "hello world"
* bcrypt -file .gitignore

# docker hub
* https://hub.docker.com/repository/docker/wlanboy/bcrypt

# usage with docker
* alias bcrypt="docker run -it --rm wlanboy/bcrypt"
* bcrypt -text "hello world"
