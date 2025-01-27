package elgamal

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

func TestNewCiphertext(t *testing.T) {
	c := qt.New(t)

	cipher := NewCiphertext(curves.New(curves.CurveTypeBN254))
	c.Assert(cipher, qt.Not(qt.IsNil))
	c.Assert(cipher.C1, qt.Not(qt.IsNil))
	c.Assert(cipher.C2, qt.Not(qt.IsNil))
}

func TestCiphertext_Encrypt(t *testing.T) {
	c := qt.New(t)

	// Create a test key pair
	curve := curves.New(curves.CurveTypeBN254)
	publicKey, _, err := GenerateKey(curve)
	c.Assert(err, qt.IsNil)

	// Test message
	msg := big.NewInt(42)

	// Test with nil k (random k generation)
	cipher := NewCiphertext(publicKey)
	encrypted, err := cipher.Encrypt(msg, publicKey, nil)
	c.Assert(err, qt.IsNil)
	c.Assert(encrypted, qt.Not(qt.IsNil))
	c.Assert(encrypted.C1, qt.Not(qt.IsNil))
	c.Assert(encrypted.C2, qt.Not(qt.IsNil))

	// Test with specific k
	k := big.NewInt(789)
	encrypted2, err := cipher.Encrypt(msg, publicKey, k)
	c.Assert(err, qt.IsNil)
	c.Assert(encrypted2, qt.Not(qt.IsNil))
}

func TestCiphertext_Add(t *testing.T) {
	c := qt.New(t)

	// Create test ciphertexts
	curve := curves.New(curves.CurveTypeBN254)
	publicKey, _, err := GenerateKey(curve)
	c.Assert(err, qt.IsNil)

	msg1 := big.NewInt(42)
	msg2 := big.NewInt(58)

	k1 := big.NewInt(789)
	k2 := big.NewInt(987)

	cipher1 := NewCiphertext(publicKey)
	encrypted1, err := cipher1.Encrypt(msg1, publicKey, k1)
	c.Assert(err, qt.IsNil)

	cipher2 := NewCiphertext(publicKey)
	encrypted2, err := cipher2.Encrypt(msg2, publicKey, k2)
	c.Assert(err, qt.IsNil)

	// Test addition
	result := NewCiphertext(publicKey)
	// Initialize result points with the first ciphertext's values
	result.C1 = encrypted1.C1
	result.C2 = encrypted1.C2
	// Now add the second ciphertext
	sum := result.Add(result, encrypted2)
	c.Assert(sum, qt.Not(qt.IsNil))
	c.Assert(sum.C1, qt.Not(qt.IsNil))
	c.Assert(sum.C2, qt.Not(qt.IsNil))
}

func TestCiphertext_SerializeDeserialize(t *testing.T) {
	c := qt.New(t)

	// Create a test ciphertext
	curve := curves.New(curves.CurveTypeBN254)
	publicKey, _, err := GenerateKey(curve)
	c.Assert(err, qt.IsNil)

	msg := big.NewInt(42)
	k := big.NewInt(789)

	cipher := NewCiphertext(publicKey)
	encrypted, err := cipher.Encrypt(msg, publicKey, k)
	c.Assert(err, qt.IsNil)

	// Test serialization
	serialized := encrypted.Serialize()
	c.Assert(serialized, qt.Not(qt.IsNil))
	c.Assert(len(serialized), qt.Equals, 128) // 4 * 32 bytes

	// Test deserialization
	deserialized := NewCiphertext(publicKey)
	err = deserialized.Deserialize(serialized)
	c.Assert(err, qt.IsNil)

	// Compare points
	x1, y1 := encrypted.C1.Point()
	x2, y2 := deserialized.C1.Point()
	c.Assert(x1.Cmp(x2), qt.Equals, 0)
	c.Assert(y1.Cmp(y2), qt.Equals, 0)

	x1, y1 = encrypted.C2.Point()
	x2, y2 = deserialized.C2.Point()
	c.Assert(x1.Cmp(x2), qt.Equals, 0)
	c.Assert(y1.Cmp(y2), qt.Equals, 0)
}

func TestCiphertext_MarshalUnmarshal(t *testing.T) {
	c := qt.New(t)

	// Create a test ciphertext
	curve := curves.New(curves.CurveTypeBN254)
	publicKey, _, err := GenerateKey(curve)
	c.Assert(err, qt.IsNil)

	msg := big.NewInt(42)
	k := big.NewInt(789)

	cipher := NewCiphertext(publicKey)
	encrypted, err := cipher.Encrypt(msg, publicKey, k)
	c.Assert(err, qt.IsNil)

	// Test marshaling
	marshaled, err := encrypted.Marshal()
	c.Assert(err, qt.IsNil)
	c.Assert(marshaled, qt.Not(qt.IsNil))

	// Test unmarshaling
	unmarshaled := NewCiphertext(publicKey)
	err = unmarshaled.Unmarshal(marshaled)
	c.Assert(err, qt.IsNil)

	// Compare points
	x1, y1 := encrypted.C1.Point()
	x2, y2 := unmarshaled.C1.Point()
	c.Assert(x1.Cmp(x2), qt.Equals, 0)
	c.Assert(y1.Cmp(y2), qt.Equals, 0)

	x1, y1 = encrypted.C2.Point()
	x2, y2 = unmarshaled.C2.Point()
	c.Assert(x1.Cmp(x2), qt.Equals, 0)
	c.Assert(y1.Cmp(y2), qt.Equals, 0)
}

func TestCiphertext_String(t *testing.T) {
	c := qt.New(t)

	// Create a test ciphertext with properly initialized points
	curve := curves.New(curves.CurveTypeBN254)
	publicKey, _, err := GenerateKey(curve)
	c.Assert(err, qt.IsNil)

	msg := big.NewInt(42)
	k := big.NewInt(789)

	cipher := NewCiphertext(publicKey)
	encrypted, err := cipher.Encrypt(msg, publicKey, k)
	c.Assert(err, qt.IsNil)

	// Test String method
	str := encrypted.String()
	c.Assert(str, qt.Not(qt.Equals), "")
	c.Assert(str, qt.Matches, `\{C1: .+, C2: .+\}`)
}

func TestCiphertext_DeserializeError(t *testing.T) {
	c := qt.New(t)

	cipher := NewCiphertext(curves.New(curves.CurveTypeBN254))

	// Test with invalid length, should panic
	c.Assert(cipher.Deserialize(make([]byte, 127)), // Should be 128
		qt.ErrorMatches, "invalid input length.*")
}
