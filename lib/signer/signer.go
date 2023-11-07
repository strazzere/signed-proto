package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	signed "github.com/strazzere/signed-proto/lib/proto"
)

func SignData(data []byte, privateKey *rsa.PrivateKey) (*signed.Buffer, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	protobufSig := &signed.Buffer{
		Data:      data,
		Signature: signature,
	}
	return protobufSig, nil
}
