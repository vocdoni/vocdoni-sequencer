package encrypt

import (
	"crypto/rand"
	"math/big"

	"github.com/vocdoni/elGamal-sandbox/ecc"
)

// Encrypt encrypts a message using the aggregated public key.
func Encrypt(message *big.Int, publicKey ecc.Point) (ecc.Point, ecc.Point, *big.Int, error) {
	order := publicKey.Order()
	// Ensure the message is within the field.
	message.Mod(message, order)

	// Generate random k.
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute C1 = k * G.
	c1 := publicKey.New()
	c1.ScalarBaseMult(k)

	// Compute s = k * PublicKey.
	s := publicKey.New()
	s.ScalarMult(publicKey, k)

	// Encode message as point M = message * G.
	m := publicKey.New()
	m.ScalarBaseMult(message)

	// Compute C2 = M + s.
	c2 := publicKey.New()
	c2.Add(m, s)

	return c1, c2, k, nil
}
