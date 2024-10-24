package main

import (
	"crypto/rand"
	"math/big"
)

// Encrypt encrypts a message using the aggregated public key.
func Encrypt(message *big.Int, publicKey *G1) (*G1, *G1, error) {
	// Ensure the message is within the field.
	message.Mod(message, Order)

	// Generate random k.
	k, err := rand.Int(rand.Reader, Order)
	if err != nil {
		return nil, nil, err
	}

	// Compute C1 = k * G.
	c1 := &G1{}
	c1.ScalarBaseMult(k)

	// Compute s = k * PublicKey.
	s := &G1{}
	s.ScalarMult(publicKey, k)

	// Encode message as point M = message * G.
	m := &G1{}
	m.ScalarBaseMult(message)

	// Compute C2 = M + s.
	c2 := &G1{}
	c2.Add(m, s)

	// Log the encryption values
	//log.Printf("Encryption: message = %s", message.String())
	//log.Printf("Encryption: k = %s", k.String())
	//log.Printf("Encryption: C1 = %s", c1.String())
	//log.Printf("Encryption: C2 = %s", c2.String())

	return c1, c2, nil
}
