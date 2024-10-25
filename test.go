package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/cloudflare/cfssl/helpers"
)

var HTTPClient = http.DefaultClient

const KeyUsageCRLSign = 64

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota

	MD2WithRSA  // Unsupported.
	MD5WithRSA  // Only supported for signing, not verification.
	SHA1WithRSA // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1   // Unsupported.
	DSAWithSHA256 // Unsupported.
	ECDSAWithSHA1 // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	PureEd25519
)

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

type SignatureAlgorithm int

func fetchAndParseCRL(url string) (*x509.RevocationList, error) {
	// Create an HTTP client
	HTTPClient := &http.Client{}

	// Fetch the CRL from the URL
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL: %v", err)
	}
	defer resp.Body.Close()

	// Check if the status code indicates success
	if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL, invalid status code")
	}

	// Read the CRL body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL body: %v", err)
	}

	// Parse the CRL
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %v", err)
	}

	// var shouldFetchCRL = true

	// if !crl.HasExpired(time.Now()) {
	// 	shouldFetchCRL = false
	// }

	// fmt.Println(crl.HasExpired(time.Now()))
	// fmt.Println(shouldFetchCRL)
	// issuer := getIssuer(nil)
	fmt.Println(time.Now().Before(crl.NextUpdate))
	fmt.Println((crl.NextUpdate))
	fmt.Println(crl.SignatureAlgorithm, crl.Signature)
	return crl, err

	// Return the parsed CRL
	// for _, revoked := range crl.TBSCertList.RevokedCertificates {
	// 	fmt.Println("hi", revoked.SerialNumber)
	// }
	// return nil, nil
}

func main() {
	vaultUrl := "https://hanarp-int-kv-westus2.vault.azure.net/"
	opts := azidentity.DefaultAzureCredentialOptions{
		AdditionallyAllowedTenants: []string{"*"},
	}
	cred, err := azidentity.NewDefaultAzureCredential(&opts)
	client, err := azsecrets.NewClient(vaultUrl, cred, nil)
	if err != nil {
		fmt.Printf("Failed to create client: %v", err)
	} else {
		fmt.Printf("Client created successfully")
	}

	secretName := "hanarp-int-identity-westus2"
	resp, err := client.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		fmt.Printf("Failed to get secret: %v", err)
		os.Exit(1)
	}

	// Decode and format
	decodedCert, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err := convertToPEM(decodedCert); err != nil {
		fmt.Println("Error:", err)
	}

	cert, err := LoadCertificate("certificate.pem")
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		return
	}

	fmt.Println(cert.CRLDistributionPoints)
	os.Exit(1)
	// fmt.Println("INT cert: ", decodedCert)
	// fmt.Printf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", base64.StdEncoding.EncodeToString(decodedCert))
	// v := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", base64.StdEncoding.EncodeToString(decodedCert))
	// _, err = mustParse(string(decodedCert))
	// fmt.Println("INT cert: ", err)
	// Example URL
	// url := "http://crl.microsoft.com/pkiinfra/CRL/AME%20Infra%20CA%2002(4).crl"

	// Fetch and parse the CRL

	// crl, err := fetchAndParseCRL(url)

	// A Comodo intermediate CA certificate with issuer url, CRL url and OCSP url
	var goodComodoCA, _ = mustParse(`-----BEGIN CERTIFICATE-----
MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy
MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh
bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh
bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0
Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6
ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51
UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n
c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY
MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz
30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG
BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv
bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB
AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E
T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v
ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p
mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/
e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps
P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY
dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc
2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG
V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4
HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX
j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII
0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap
lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf
+AZxAeKCINT+b72x
-----END CERTIFICATE-----`)

	// goodComodoCA.CRLDistributionPoints[0] = "http://crl.microsoft.com/pkiinfra/crl/AME%20INFRA%20CA%2001.crl"
	// url := goodComodoCA.CRLDistributionPoints[0]
	// goodComodoCA.CRLDistributionPoints[0] = ""
	fmt.Println(goodComodoCA.CRLDistributionPoints)
	fmt.Println(goodComodoCA.IssuingCertificateURL)

	// fmt.Println(time.Now().Before(goodComodoCA.CRLDistributionPoints[0].TBSCertList.NextUpdate))
	issuer := getIssuer(goodComodoCA)
	url := goodComodoCA.CRLDistributionPoints[0]
	crl, err := fetchAndParseCRL(url)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// 	return
	// } else {
	// 	fmt.Printf("CRL fetched from url with error %v", err)
	// }

	err = crl.CheckSignatureFrom(issuer)
	if err != nil {
		fmt.Printf("failed to verify CRL1\n: %v\n \n", err)
	}

	fmt.Println(issuer.PublicKeyAlgorithm, issuer.Version, issuer.BasicConstraintsValid, issuer.KeyUsage&KeyUsageCRLSign)
	fmt.Println(crl.SignatureAlgorithm)
	fmt.Printf("type of CRL TBS %T", issuer.PublicKey)
	// fmt.Printf("type of CRL TBS %v", string(hex.EncodeToString(crl.RawTBSRevocationList)))
	// fmt.Printf("type of CRL TBS %v", string(hex.EncodeToString(crl.Signature)))
	// err = CheckSignature1(crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature, issuer.PublicKey, true)
	err = issuer.CheckSignature(crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature)
	if err != nil {
		fmt.Printf("failed to verify CRL: %v", err)
	} else {
		fmt.Printf("Cert verification suuucceded: %v", err)
	}
	// revoked, ok, err := revoke.VerifyCertificateError(goodComodoCA)

	// if !ok {
	// 	fmt.Println("is cert revoked: %v %v", revoked, ok)
	// }

	// CRL was successfully parsed
	// fmt.Println("CRL retrieved and parsed successfully:", revoked, ok, err)
	// fmt.Println("CRL retrieved and parsed successfully", issuer.CRLDistributionPoints)
}

func mustParse(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		panic("Invalid PEM data.")
	} else if block.Type != "CERTIFICATE" {
		panic("Invalid PEM type.")
	}

	cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		return nil, err

	}
	return cert, nil
}

func getIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	in, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(in)
	if p != nil {
		return helpers.ParseCertificatePEM(in)
	}

	return x509.ParseCertificate(in)
}

// func CheckSignature1(algo x509.SignatureAlgorithm, signed []byte, signature []byte, publicKey any, allowSHA1 bool) (err error) {
// 	var hashType crypto.Hash

// 	hashType = crypto.SHA256
// 	// pubKeyAlgo := "SHA-256"
// 	switch hashType {
// 	case crypto.Hash(0):

// 	default:
// 		if !hashType.Available() {
// 			return ErrUnsupportedAlgorithm
// 		}
// 		h := hashType.New()
// 		h.Write(signed)
// 		signed = h.Sum(nil)
// 	}

// 	switch pub := publicKey.(type) {
// 	case *rsa.PublicKey:
// 		fmt.Println("Hello there", isRSAPSS(algo))
// 		if isRSAPSS(algo) {
// 			err = rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
// 			fmt.Println("Error in verify PSS ", err)
// 			return err
// 		} else {
// 			err = VerifyPKCS1v15(pub, hashType, signed, signature)
// 			return err
// 		}
// 	}
// 	return ErrUnsupportedAlgorithm
// }

func isRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case 13, 14, 15:
		return true
	default:
		return false
	}
}

var ErrVerification = errors.New("crypto/rsa: verification error")

// func VerifyPKCS1v15(pub *crypto.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
// 	if boring.Enabled {
// 		bkey, err := boringPublicKey(pub)
// 		if err != nil {
// 			return err
// 		}
// 		if err := boring.VerifyRSAPKCS1v15(bkey, hash, hashed, sig); err != nil {
// 			return ErrVerification
// 		}
// 		return nil
// 	}

// 	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
// 	if err != nil {
// 		return err
// 	}

// 	tLen := len(prefix) + hashLen
// 	k := pub.Size1()
// 	if k < tLen+11 {
// 		return ErrVerification
// 	}

// 	// RFC 8017 Section 8.2.2: If the length of the signature S is not k
// 	// octets (where k is the length in octets of the RSA modulus n), output
// 	// "invalid signature" and stop.
// 	if k != len(sig) {
// 		return ErrVerification
// 	}

// 	em, err := encrypt(pub, sig)
// 	if err != nil {
// 		return ErrVerification
// 	}
// 	// EM = 0x00 || 0x01 || PS || 0x00 || T

// 	ok := subtle.ConstantTimeByteEq(em[0], 0)
// 	ok &= subtle.ConstantTimeByteEq(em[1], 1)
// 	ok &= subtle.ConstantTimeCompare(em[k-hashLen:k], hashed)
// 	ok &= subtle.ConstantTimeCompare(em[k-tLen:k-hashLen], prefix)
// 	ok &= subtle.ConstantTimeByteEq(em[k-tLen-1], 0)

// 	for i := 2; i < k-tLen-1; i++ {
// 		ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
// 	}

// 	if ok != 1 {
// 		return ErrVerification
// 	}

// 	return nil
// }

// func boringPublicKey(c *crypto.PublicKey) (*boring.PublicKeyRSA, error) {
// 	panic("boringcrypto: not available")
// }

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

// // for or by this public key will have the same size.
// func (pub *crypto.PublicKey) Size1() int {
// 	return (pub.N.BitLen() + 7) / 8
// }

func convertToPEM(derBytes []byte) error {
	// Create the PEM block for a standard X.509 certificate
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// Print the PEM format to the console
	fmt.Println("PEM format:")
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		return fmt.Errorf("error encoding to PEM: %w", err)
	}

	// Optionally, save the PEM to a file
	fileName := "certificate.pem"
	pemFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("error creating PEM file: %w", err)
	}
	defer pemFile.Close()

	if err := pem.Encode(pemFile, pemBlock); err != nil {
		return fmt.Errorf("error writing to PEM file: %w", err)
	}

	fmt.Printf("PEM conversion successful: %s\n", fileName)
	return nil
}

func LoadCertificate(filePath string) (*x509.Certificate, error) {
	// Read the file
	pemData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
