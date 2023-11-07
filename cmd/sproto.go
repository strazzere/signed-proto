package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/golang/protobuf/proto"

	signed "github.com/strazzere/signed-proto/lib/proto"
	"github.com/strazzere/signed-proto/lib/signer"
	"github.com/strazzere/signed-proto/lib/verifier"
)

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(keyFile)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privateKey, nil
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	keyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	block, _ := pem.Decode(keyFile)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert to *rsa.PublicKey")
	}

	return publicKey, nil
}

func main() {
	sign := flag.Bool("sign", false, "Enable signing mode")
	verify := flag.Bool("verify", false, "Enable verification mode")
	privateKeyFile := flag.String("privateKey", "", "Path to private key file")
	publicKeyFile := flag.String("publicKey", "", "Path to public key file")
	bufferFile := flag.String("buffer", "", "Path to file containing buffer data or signed protobuf")
	flag.Parse()

	if *sign && *verify {
		panic("Cannot use both sign and verify modes at the same time")
	}

	if (*sign || *verify) && (*privateKeyFile == "" || *bufferFile == "") {
		panic("Private key and buffer file are required for signing")
	}

	if (*verify) && (*publicKeyFile == "" || *bufferFile == "") {
		panic("Public key and buffer file are required for verifying")
	}

	buffer, err := os.ReadFile(*bufferFile)
	if err != nil {
		panic(fmt.Sprintf("Error reading buffer file: %v", err))
	}

	if *sign {
		privateKey, err := loadPrivateKey(*privateKeyFile)
		if err != nil {
			panic(fmt.Sprintf("Error loading private key: %v", err))
		}

		buffer, err := os.ReadFile(*bufferFile)
		if err != nil {
			panic(fmt.Sprintf("Error reading buffer file: %v", err))
		}

		signature, err := signer.SignData(buffer, privateKey)
		if err != nil {
			log.Fatalf("Failed to sign data: %v", err)
		}

		fmt.Printf("Signature: %s\n", signature)
	} else if *verify {
		publicKey, err := loadPublicKey(*publicKeyFile)
		if err != nil {
			log.Fatalf("Error loading public key: %v", err)
		}

		signedBuffer := &signed.Buffer{}
		if err := proto.Unmarshal(buffer, signedBuffer); err != nil {
			log.Fatalln("Failed to parse address book:", err)
		}

		valid, err := verifier.VerifySignature(signedBuffer, publicKey)
		if err != nil {
			log.Fatalf("Failed to verify signature: %v", err)
		}

		if valid {
			fmt.Println("Signature is valid")
		} else {
			fmt.Println("Signature is not valid")
		}
	} else {
		flag.PrintDefaults()
	}
}
