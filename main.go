// package main

// import (
// 	"bytes"
// 	"crypto/x509"
// 	"encoding/base64"
// 	"encoding/json"
// 	"fmt"
// 	"hello/models"
// 	"io/ioutil"
// 	"log"
// 	"math/big"
// 	"net/http"
// 	"os"
// 	"strconv"
// 	"time"
// )

// func main() {
// 	req, err := http.NewRequest(http.MethodGet, "https://hackattic.com/challenges/tales_of_ssl/problem?access_token=838eb697dc0f1219", nil)
// 	if err != nil {
// 		fmt.Printf("Error creating http request: %v", err)
// 		os.Exit(1)
// 	}

// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		fmt.Printf("Error creating request: %v", err)
// 		os.Exit(1)
// 	}

// 	fmt.Printf("Client got response!\n")
// 	fmt.Printf("Status code of response: %s\n", resp.Status)

// 	defer resp.Body.Close()
// 	resBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Printf("Could not read response body: %s\n", err)
// 		os.Exit(1)
// 	}

// 	fmt.Printf("Response body: %s \n", resBody)
// 	var cert models.Cert
// 	err = json.Unmarshal(resBody, &cert)
// 	if err != nil {
// 		fmt.Printf("Error unmarshalling json %s: \n", err)
// 		os.Exit(1)
// 	}

// 	fmt.Println("Private key: ", cert.PrivateKey)
// 	fmt.Println("Cert domain serial number:", cert.Data.Serial_number)
// 	fmt.Println("Cert domain input:", cert.Data.Domain)
// 	fmt.Println("Cert country input:", cert.Data.Country)

// 	// out, err := exec.Command("openssl", "help").Output()

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// fmt.Println(string(out))

// 	keyBytes, err := base64.StdEncoding.DecodeString(cert.PrivateKey)
// 	if err != nil {
// 		fmt.Printf("Error in creating bytes data from cert: %v", keyBytes)
// 	}

// 	pkey, err := x509.ParsePKCS1PrivateKey(keyBytes)
// 	if err != nil {
// 		fmt.Printf("Failed to parse private key with error: %v", err)
// 	}

// 	// fmt.Println(pkey.PublicKey)
// 	// fmt.Println(pkey.PublicKey)
// 	// fmt.Printf("uouo %T", pkey.PublicKey)

// 	serialNumber, _ := strconv.Atoi(cert.Data.Serial_number)

// 	notBefore := time.Now()
// 	notAfter := notBefore.Add(time.Hour * 24 * 30) // set expiry to 30 days from now

// 	certTemplate := x509.Certificate{
// 		SerialNumber:        big.NewInt(int64(serialNumber)),
// 		PermittedDNSDomains: []string{cert.Data.Domain},
// 		NotBefore:           notBefore,
// 		NotAfter:            notAfter,
// 	}

// 	generatedCert, err := x509.CreateCertificate(nil, &certTemplate, &certTemplate, &pkey.PublicKey, pkey)
// 	fmt.Println("Error in generating cert: ", err)
// 	// fmt.Println("generated cert: ", generatedCert)
// 	certDER, err := x509.ParseCertificate(generatedCert)
// 	if err != nil {
// 		fmt.Printf("Error while parsing DER cert. Error: %+v", err)
// 	}

// 	certificate := base64.StdEncoding.EncodeToString(certDER.Raw)
// 	// fmt.Println(certificate)
// 	// var solution models.Solution
// 	solution := models.Solution{
// 		Certificate: certificate,
// 	}

// 	fmt.Println(solution)
// 	jsonBody, err := json.Marshal(solution)
// 	if err != nil {
// 		fmt.Printf("Error in marshalling solution: %v", err)
// 		os.Exit(1)
// 	}

// 	bodyReader := bytes.NewReader(jsonBody)

// 	requestURL := fmt.Sprintf("https://hackattic.com/challenges/tales_of_ssl/solve?access_token=b3a07ea59189199a")

// 	req, err = http.NewRequest(http.MethodPost, requestURL, bodyReader)
// 	if err != nil {
// 		fmt.Printf("Error creating http request: %v", err)
// 		os.Exit(1)
// 	}

// 	req.Header.Set("Content-Type", "application/json")
// 	res, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		fmt.Printf("client: error making http request: %s\n", err)
// 		os.Exit(1)
// 	}

// 	fmt.Println(res)
// 	// base64.StdEncoding.DecodeString(string(generatedCert))

// }
