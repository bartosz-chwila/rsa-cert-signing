package rsasign_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	rsasign "github.com/bartosz-chwila/rsa-cert-signing"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	// given
	msg := "test-message"

	// when
	signedMessage, err := rsasign.Sign([]byte(msg))

	// then
	require.NoError(t, err)
	publicParsed, err := x509.ParsePKCS1PublicKey(signedMessage.PublicKey)
	require.NoError(t, err)
	err = rsa.VerifyPSS(publicParsed, crypto.SHA512, signedMessage.HashSum, signedMessage.Signature, &rsa.PSSOptions{})
	require.NoError(t, err)
}
