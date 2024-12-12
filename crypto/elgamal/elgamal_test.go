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

func TestCheckK(t *testing.T) {
	// Setup a curve point
	curve, err := curves.New(curves.CurveTypeBN254)
	qt.Assert(t, err, qt.IsNil)

	// Generate a key pair
	pubKey, privKey, err := GenerateKey(curve)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Define a message
	msg := big.NewInt(42)
	maxMsg := uint64(100)

	// Encrypt the message
	c1, c2, k, err := Encrypt(pubKey, msg)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Check that k is indeed the one used
	if !CheckK(c1, k) {
		t.Fatalf("CheckK failed: it should have found that this k was used")
	}

	// Try a wrong k
	wrongK := big.NewInt(999999) // a random different k
	if CheckK(c1, wrongK) {
		t.Fatalf("CheckK failed: it should not have matched this wrong k")
	}

	// Bonus: try decrypting to ensure correctness (not necessary for CheckK logic)
	M, mInt, err := Decrypt(pubKey, privKey, c1, c2, maxMsg)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if mInt.Cmp(msg) != 0 {
		t.Fatalf("Decryption mismatch: got %s, want %s", mInt.String(), msg.String())
	}

	// Just ensure M was computed
	if M == nil {
		t.Fatalf("M point is nil after decrypt")
	}
}
