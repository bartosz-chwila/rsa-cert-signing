package rsasign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
)

type SignedMessage struct {
	Signature []byte
	PublicKey []byte
	HashSum   []byte
}

func Sign(toSign []byte) (*SignedMessage, error) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	toSignHash := sha512.New()
	_, err = toSignHash.Write([]byte(toSign))
	if err != nil {
		return nil, err
	}

	toSignHashSum := toSignHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA512, toSignHashSum, nil)
	if err != nil {
		return nil, err
	}

	return &SignedMessage{Signature: signature, PublicKey: x509.MarshalPKCS1PublicKey(&private.PublicKey), HashSum: toSignHashSum}, nil
}
