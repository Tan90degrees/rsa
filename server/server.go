package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
)

const PRIKEY string = "privateKey.pem"

func Decrypt(path string, msg []byte) []byte {
	fp, _ := os.Open(path)
	defer fp.Close()
	fs, _ := fp.Stat()
	buf := make([]byte, fs.Size())
	fp.Read(buf)
	block, _ := pem.Decode(buf)
	pri, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	decryptMsg, _ := rsa.DecryptPKCS1v15(rand.Reader, pri, msg)
	return decryptMsg
}

func Server() {
	s := make([]byte, 256)
	authSocket, err := net.Listen("tcp", ":4321")
	CheckError(err)
	defer authSocket.Close()
	authConn, err := authSocket.Accept()
	CheckError(err)
	defer authConn.Close()
	fmt.Print("Accept from:", authConn.RemoteAddr())
	_, err = authConn.Read(s)
	CheckError(err)
	msg := Decrypt(PRIKEY, s)
	fmt.Println(string(msg))
}
