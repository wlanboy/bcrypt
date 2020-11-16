package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	textPtr := flag.String("text", "", "Text to bcryt hash.")
	filePtr := flag.String("file", "", "File to bcryt hash.")

	flag.Parse()

	if *textPtr == "" && *filePtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *textPtr != "" {
		hashAndSalt([]byte(*textPtr))
	} else {
		if fileIsPresent(*filePtr) {
			bytes, err := ioutil.ReadFile(*filePtr)
			if err != nil {
				fmt.Print(err)
			}
			hashAndSalt(bytes)
		} else {
			fmt.Println("file not found")
		}
	}
}

func hashAndSalt(text []byte) {
	hash, err := bcrypt.GenerateFromPassword(text, bcrypt.MinCost)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(hash))
}

func fileIsPresent(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
