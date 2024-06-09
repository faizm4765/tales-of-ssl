package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type required_data struct {
	domain        string
	serial_number string
	country       string
}

type cert struct {
	PrivateKey string
	Data       required_data
}

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
	fmt.Printf("Status code of response: %d\n", resp.Status)

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Could not read response body: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response body: %s \n", resBody)
	// fmt.Printf("Response body private key: %s \n", )
	// fmt.Printf("Response body required data: %s \n", resBody.required_data)
}
