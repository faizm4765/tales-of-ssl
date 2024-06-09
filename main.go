package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	resp, err := http.Get("https://hackattic.com/challenges/tales_of_ssl/problem?access_token=b3a07ea59189199a")
	if err != nil {
		fmt.Printf("Error making http request: ", err)
		os.Exit(1)
	}

	fmt.Printf("Client got response!\n")
	fmt.Printf("Status code of response: ", resp.Status)
}
