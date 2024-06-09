package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	req, err := http.NewRequest(http.MethodGet, "https://hackattic.com/challenges/tales_of_ssl/problem?access_token=b3a07ea59189199a", nil)
	if err != nil {
		fmt.Printf("Error creating http request: ", err)
		os.Exit(1)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error creating request: ", err)
		os.Exit(1)
	}
	fmt.Printf("Client got response!\n")
	fmt.Printf("Status code of response: ", resp.Status)
}
