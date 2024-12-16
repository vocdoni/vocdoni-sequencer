package elgamal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

// Ciphertext represents an ElGamal encrypted message with homomorphic properties.
// It is a wrapper for convenience of the elGamal ciphersystem that encapsulates the two points of a ciphertext.
type Ciphertext struct {
	CurveType string    `json:"curveType"`
	C1        ecc.Point `json:"c1"`
	C2        ecc.Point `json:"c2"`
}

// NewCiphertext creates a new Ciphertext with the given curve type.
// The curve type must be one of the supported curves by crypto/ecc/curves package.
func NewCiphertext(curveType string) *Ciphertext {
	return &Ciphertext{
		C1:        curves.New(curveType),
		C2:        curves.New(curveType),
		CurveType: curveType,
	}
}

// Encrypt encrypts a message using the public key provided as elliptic curve point.
// The randomness k can be provided or nil to generate a new one.
func (z *Ciphertext) Encrypt(message *big.Int, publicKey ecc.Point, k *big.Int) (*Ciphertext, error) {
	var err error
	if k == nil {
		k, err = RandK()
		if err != nil {
			return nil, fmt.Errorf("elgamal encryption failed: %w", err)
		}
	}
	c1, c2, err := EncryptWithK(publicKey, message, k)
	if err != nil {
		return nil, fmt.Errorf("elgamal encryption failed: %w", err)
	}
	return &Ciphertext{
		CurveType: z.CurveType,
		C1:        c1,
		C2:        c2,
	}, nil
}

// Add adds two Ciphertext and stores the result in z, which is also returned.
func (z *Ciphertext) Add(x, y *Ciphertext) *Ciphertext {
	z.C1.SafeAdd(x.C1, y.C1)
	z.C2.SafeAdd(x.C2, y.C2)
	return z
}

// Serialize returns a slice of len 4*32 bytes,
// representing the C1.X, C1.Y, C2.X, C2.Y as little-endian.
func (z *Ciphertext) Serialize() []byte {
	x1, y1 := z.C1.Point()
	x2, y2 := z.C2.Point()
	var buf bytes.Buffer
	for _, bi := range []*big.Int{
		x1,
		y1,
		x2,
		y2,
	} {
		if _, err := buf.Write(arbo.BigIntToBytes(32, bi)); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}

// Deserialize reconstructs a Ciphertext from a slice of bytes.
// The input must be of len 4*32 bytes, representing the C1.X, C1.Y, C2.X, C2.Y as little-endian.
func (z *Ciphertext) Deserialize(data []byte) error {
	const fieldSize = 32 // Each field element is 32 bytes
	expectedLen := 4 * fieldSize

	// Validate the input length
	if len(data) != expectedLen {
		return fmt.Errorf("invalid input length: got %d bytes, expected %d bytes", len(data), expectedLen)
	}

	// Helper function to extract *big.Int from a 32-byte slice
	readBigInt := func(offset int) *big.Int {
		return arbo.BytesToBigInt(data[offset : offset+fieldSize])
	}

	// Deserialize each field
	x1 := readBigInt(0 * fieldSize)
	y1 := readBigInt(1 * fieldSize)
	x2 := readBigInt(2 * fieldSize)
	y2 := readBigInt(3 * fieldSize)

	// Set the points and store the returned points
	z.C1 = z.C1.SetPoint(x1, y1)
	z.C2 = z.C2.SetPoint(x2, y2)

	return nil
}

// Marshal converts Ciphertext to a byte slice.
func (z *Ciphertext) Marshal() ([]byte, error) {
	return json.Marshal(z)
}

// Unmarshal populates Ciphertext from a byte slice.
func (z *Ciphertext) Unmarshal(data []byte) error {
	return json.Unmarshal(data, z)
}

// String returns a string representation of the Ciphertext.
func (z *Ciphertext) String() string {
	if z == nil || z.C1 == nil || z.C2 == nil {
		return "{C1: nil, C2: nil}"
	}
	return fmt.Sprintf("{C1: %s, C2: %s}", z.C1.String(), z.C2.String())
}
