package elgamal

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

func TestGenerateKey(t *testing.T) {
	curve, err := curves.New(curves.CurveTypeBN254)
	qt.Assert(t, err, qt.IsNil)

	publicKey, privateKey, err := GenerateKey(curve)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, publicKey, qt.Not(qt.IsNil))
	qt.Assert(t, privateKey, qt.Not(qt.IsNil))

	// Check if publicKey = privateKey * G
	testPoint := curve.New()
	testPoint.SetGenerator()
	testPoint.ScalarMult(testPoint, privateKey)
	qt.Assert(t, testPoint.Equal(publicKey), qt.IsTrue)
}

func TestEncryptDecrypt(t *testing.T) {
	curve, err := curves.New(curves.CurveTypeBN254)
	qt.Assert(t, err, qt.IsNil)

	publicKey, privateKey, err := GenerateKey(curve)
	qt.Assert(t, err, qt.IsNil)

	maxMessage := uint64(1000)

	for _, m := range []uint64{0, 1, 42, 999} {
		msg := big.NewInt(int64(m))
		c1, c2, k, err := Encrypt(publicKey, msg)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, k, qt.Not(qt.IsNil))

		M, recoveredMsg, err := Decrypt(publicKey, privateKey, c1, c2, maxMessage)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, recoveredMsg.String(), qt.DeepEquals, msg.String())

		// Check M = m * G
		testPoint := curve.New()
		testPoint.SetGenerator()
		testPoint.ScalarMult(testPoint, msg)
		qt.Assert(t, testPoint.Equal(M), qt.IsTrue)
	}
}
