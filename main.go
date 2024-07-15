package main

import (
	"encoding/json"
	"fmt"
	"hello/models"
	"io/ioutil"
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
	fmt.Printf("Status code of response: %s\n", resp.Status)

	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Could not read response body: %s\n", err)
		os.Exit(1)
	}

	// fmt.Printf("Response body: %s \n", resBody)
	var cert models.Cert
	err = json.Unmarshal(resBody, &cert)
	if err != nil {
		fmt.Printf("Error unmarshalling json %s: \n", err)
		os.Exit(1)
	}

	// fmt.Println("Cert private key:", cert.PrivateKey)
	fmt.Println("Cert domain input:", cert.Data.Domain)
	fmt.Println("Cert country input:", cert.Data.Country)
}
