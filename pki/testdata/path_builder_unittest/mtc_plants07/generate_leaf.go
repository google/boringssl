package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func do() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	icaTempl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "ICA 1"},
		IsCA: true,
		SerialNumber: big.NewInt(1),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2030, time.December, 31, 23, 59, 59, 0, time.UTC),
	}
	ica, err := x509.CreateCertificate(rand.Reader, icaTempl, icaTempl, key.Public(), key)
	if err != nil {
		return err
	}
	icaCert, err := x509.ParseCertificate(ica)
	if err != nil {
		return err
	}

	leafTempl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Leaf 1"},
		SerialNumber: big.NewInt(1),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2030, time.December, 31, 23, 59, 59, 0, time.UTC),
		DNSNames: []string{"example.com"},
	}

	cert, err := x509.CreateCertificate(rand.Reader, leafTempl, icaTempl, leafKey.Public(), key)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	pem.Encode(os.Stdout, pemBlock)
	ica_spki := base64.StdEncoding.EncodeToString(icaCert.RawSubjectPublicKeyInfo)
	fmt.Printf("ICA SPKI: %s\n", ica_spki)
	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}
}
