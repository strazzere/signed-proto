package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSignData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate private key: %v", err)
	}

	testData := []byte("test data for signing")
	signature, err := SignData(testData, privateKey)
	if err != nil {
		t.Errorf("Failed to sign data: %v", err)
	}

	if signature == nil {
		t.Error("Signature is nil")
	}
}
