package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const PRIKEY string = "privateKey.pem"
const PUBKEY string = "publicKey.pem"

func GenKey(strength int) {
	if IsThere(PRIKEY) || IsThere(PUBKEY) {
		fmt.Println("There have been keys.")
		return
	}
	// Private key
	priKey, err := rsa.GenerateKey(rand.Reader, strength)
	CheckError(err)
	x509priKey := x509.MarshalPKCS1PrivateKey(priKey)
	priFp, err := os.Create(PRIKEY)
	CheckError(err)
	defer priFp.Close()
	priPemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509priKey,
	}
	pem.Encode(priFp, &priPemBlock)

	// Public key
	pubFp, err := os.Create(PUBKEY)
	CheckError(err)
	defer pubFp.Close()
	pubKey := priKey.PublicKey
	x509pubKey := x509.MarshalPKCS1PublicKey(&pubKey)
	pubPemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509pubKey,
	}
	pem.Encode(pubFp, &pubPemBlock)
}
