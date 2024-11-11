package encrypt

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/vocdoni/elGamal-sandbox/ecc"
)

// RandK function generates a random k value for encryption.
func RandK() (*big.Int, error) {
	kBytes := make([]byte, 32)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}
	k := new(big.Int).SetBytes(kBytes)
	return k, nil
}

// Encrypt function encrypts a message using the public key provided as
// elliptic curve point. It generates a random k and returns the two points
// that represent the encrypted message and the random k used to encrypt it.
// It returns an error if any.
func Encrypt(publicKey ecc.Point, msg *big.Int) (ecc.Point, ecc.Point, *big.Int, error) {
	k, err := RandK()
	if err != nil {
		return nil, nil, nil, err
	}
	// encrypt the message using the random k generated
	c1, c2, err := EncryptWithK(publicKey, msg, k)
	if err != nil {
		return nil, nil, nil, err
	}
	return c1, c2, k, nil
}

// EncryptWithK function encrypts a message using the public key provided as
// elliptic curve point and the random k value provided. It returns the two
// points that represent the encrypted message and error if any.
func EncryptWithK(pubKey ecc.Point, msg, k *big.Int) (ecc.Point, ecc.Point, error) {
	order := pubKey.Order()
	// ensure the message is within the field
	msg.Mod(msg, order)
	// compute C1 = k * G
	c1 := pubKey.New()
	c1.ScalarBaseMult(k)
	// compute s = k * pubKey
	s := pubKey.New()
	s.ScalarMult(pubKey, k)
	// encode message as point M = message * G
	m := pubKey.New()
	m.ScalarBaseMult(msg)
	// compute C2 = M + s
	c2 := pubKey.New()
	c2.Add(m, s)
	return c1, c2, nil
}
