package verifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	signed "github.com/strazzere/signed-proto/lib/proto"
)

func VerifySignature(protobufSig *signed.Buffer, publicKey *rsa.PublicKey) (bool, error) {
	hashed := sha256.Sum256(protobufSig.GetData())
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], protobufSig.GetSignature())
	if err != nil {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}
