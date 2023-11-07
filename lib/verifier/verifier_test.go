package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/strazzere/signed-proto/lib/signer"
)

func TestVerifySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate private key: %v", err)
	}

	testData := []byte("test data for signing")
	signature, err := signer.SignData(testData, privateKey)
	if err != nil {
		t.Errorf("Failed to sign data: %v", err)
	}

	publicKey := &privateKey.PublicKey
	valid, err := VerifySignature(signature, publicKey)
	if err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}
