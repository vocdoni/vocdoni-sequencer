package elgamal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/fxamacker/cbor/v2"
	"github.com/vocdoni/arbo"
	gelgamal "github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

// sizes in bytes needed to serialize a Ballot
const (
	sizeCoord            = crypto.SerializedFieldSize
	sizePoint            = 2 * sizeCoord
	sizeCiphertext       = 2 * sizePoint
	SerializedBallotSize = circuits.FieldsPerBallot * sizeCiphertext
)

// BigIntsPerCiphertext is 4 since each Ciphertext has C1.X, C1.Y, C2.X and
// C2.Y coords
const BigIntsPerCiphertext = 4

type Ballot struct {
	CurveType   string                                `json:"curveType"`
	Ciphertexts [circuits.FieldsPerBallot]*Ciphertext `json:"ciphertexts"`
}

// NewBallot creates a new Ballot for the given curve.
func NewBallot(curve ecc.Point) *Ballot {
	z := &Ballot{
		CurveType:   curve.Type(),
		Ciphertexts: [circuits.FieldsPerBallot]*Ciphertext{},
	}
	for i := range z.Ciphertexts {
		z.Ciphertexts[i] = NewCiphertext(curve)
	}
	return z
}

// Encrypt encrypts a message using the public key provided as elliptic curve
// point. The randomness k can be provided or nil to generate a new one.
func (z *Ballot) Encrypt(message [circuits.FieldsPerBallot]*big.Int, publicKey ecc.Point, k *big.Int) (*Ballot, error) {
	for i := range z.Ciphertexts {
		if _, err := z.Ciphertexts[i].Encrypt(message[i], publicKey, k); err != nil {
			return nil, err
		}
	}
	return z, nil
}

// Add adds two Ballots and stores the result in the receiver, which is also
// returned.
func (z *Ballot) Add(x, y *Ballot) *Ballot {
	for i := range z.Ciphertexts {
		z.Ciphertexts[i].Add(x.Ciphertexts[i], y.Ciphertexts[i])
	}
	return z
}

// BigInts returns a slice with 8*4 BigInts, namely the coords of each
// Ciphertext C1.X, C1.Y, C2.X, C2.Y as little-endian, in reduced twisted
// edwards form.
func (z *Ballot) BigInts() []*big.Int {
	list := []*big.Int{}
	for _, z := range z.Ciphertexts {
		c1x, c1y := z.C1.Point()
		c2x, c2y := z.C2.Point()
		list = append(list, c1x, c1y, c2x, c2y)
	}
	return list
}

// Serialize returns a slice of len N*4*32 bytes,
// representing each Ciphertext C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ballot) Serialize() []byte {
	var buf bytes.Buffer
	for _, z := range z.Ciphertexts {
		buf.Write(z.Serialize())
	}
	return buf.Bytes()
}

// Deserialize reconstructs a Ballot from a slice of bytes.
// The input must be of len N*4*32 bytes (otherwise it returns an error),
// representing each Ciphertext C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ballot) Deserialize(data []byte) error {
	// Validate the input length
	if len(data) != SerializedBallotSize {
		return fmt.Errorf("invalid input length for Ballot: got %d bytes, expected %d bytes", len(data), SerializedBallotSize)
	}
	for i := range z.Ciphertexts {
		err := z.Ciphertexts[i].Deserialize(data[i*sizeCiphertext : (i+1)*sizeCiphertext])
		if err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON encodes a Ballot into JSON without using an extra aux type.
func (z *Ballot) MarshalJSON() ([]byte, error) {
	// Build a map representing the ballot.
	m := map[string]interface{}{
		"curveType": z.CurveType,
	}

	// For the ciphertexts we build a slice. Each ciphertext is expected
	// to marshal itself properly (its points must implement MarshalJSON).
	cts := make([]interface{}, len(z.Ciphertexts))
	for i, ct := range z.Ciphertexts {
		cts[i] = ct
	}
	m["ciphertexts"] = cts
	return json.Marshal(m)
}

// UnmarshalJSON decodes JSON data into a Ballot.
// It reads a "curveType" and a "ciphertexts" array and then creates
// concrete ciphertexts using the provided curve type.
func (z *Ballot) UnmarshalJSON(data []byte) error {
	// First, decode into a map of raw JSON values.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// Extract the curve type.
	if raw, ok := m["curveType"]; ok {
		if err := json.Unmarshal(raw, &z.CurveType); err != nil {
			return fmt.Errorf("failed to unmarshal curveType: %w", err)
		}
	} else {
		return fmt.Errorf("missing curveType field")
	}

	// Extract the ciphertexts.
	var rawCts []json.RawMessage
	if raw, ok := m["ciphertexts"]; ok {
		if err := json.Unmarshal(raw, &rawCts); err != nil {
			return fmt.Errorf("failed to unmarshal ciphertexts: %w", err)
		}
	} else {
		return fmt.Errorf("missing ciphertexts field")
	}

	if len(rawCts) != circuits.FieldsPerBallot {
		return fmt.Errorf("expected %d ciphertexts, got %d", circuits.FieldsPerBallot, len(rawCts))
	}

	// Unmarshal each ciphertext using the Ballot's curve type.
	var cts [circuits.FieldsPerBallot]*Ciphertext
	for i, raw := range rawCts {
		ct := new(Ciphertext)
		if err := ct.unmarshalJSONWithCurve(z.CurveType, raw); err != nil {
			return fmt.Errorf("failed to unmarshal ciphertext[%d]: %w", i, err)
		}
		cts[i] = ct
	}
	z.Ciphertexts = cts
	return nil
}

// Helper: unmarshalJSONWithCurve decodes a ciphertext from JSON given a curve type.
func (ct *Ciphertext) unmarshalJSONWithCurve(curveType string, data json.RawMessage) error {
	// We expect the ciphertext JSON to have "c1" and "c2".
	var tmp struct {
		C1 json.RawMessage `json:"c1"`
		C2 json.RawMessage `json:"c2"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal ciphertext fields: %w", err)
	}

	// Create concrete points using the provided curve type.
	p1 := curves.New(curveType)
	if err := json.Unmarshal(tmp.C1, p1); err != nil {
		return fmt.Errorf("failed to unmarshal c1: %w", err)
	}
	p2 := curves.New(curveType)
	if err := json.Unmarshal(tmp.C2, p2); err != nil {
		return fmt.Errorf("failed to unmarshal c2: %w", err)
	}
	ct.C1 = p1
	ct.C2 = p2
	return nil
}

func (z *Ballot) Marshal() ([]byte, error) {
	encOpts := cbor.CoreDetEncOptions()

	em, err := encOpts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("encode artifact: %w", err)
	}
	return em.Marshal(z)
}

// Unmarshal decodes a Ballot from CBOR data.
func (z *Ballot) Unmarshal(data []byte) error {
	// decode into a temporary structure that holds the raw CBOR messages
	var tmp struct {
		CurveType   string            `cbor:"curveType"`
		Ciphertexts []cbor.RawMessage `cbor:"ciphertexts"`
	}
	if err := cbor.Unmarshal(data, &tmp); err != nil {
		return err
	}
	z.CurveType = tmp.CurveType

	if len(tmp.Ciphertexts) != circuits.FieldsPerBallot {
		return fmt.Errorf("expected %d ciphertexts, got %d", circuits.FieldsPerBallot, len(tmp.Ciphertexts))
	}

	z.Ciphertexts = [circuits.FieldsPerBallot]*Ciphertext{}
	for i, raw := range tmp.Ciphertexts {
		ct := new(Ciphertext)
		// Unmarshal the ciphertext using a helper that knows the curve type.
		if err := ct.unmarshalCBORWithCurve(tmp.CurveType, raw); err != nil {
			return err
		}
		z.Ciphertexts[i] = ct
	}
	return nil
}

// unmarshalCBORWithCurve decodes a Ciphertext from raw CBOR using the given curve type.
func (ct *Ciphertext) unmarshalCBORWithCurve(curveType string, data []byte) error {
	// decode into a temporary structure that holds the raw messages for c1 and c2
	var tmp struct {
		C1 cbor.RawMessage `cbor:"c1"`
		C2 cbor.RawMessage `cbor:"c2"`
	}
	if err := cbor.Unmarshal(data, &tmp); err != nil {
		return err
	}
	// Create new concrete points using the curve type.
	p1 := curves.New(curveType)
	if err := p1.UnmarshalCBOR(tmp.C1); err != nil {
		return fmt.Errorf("failed to unmarshal c1: %w", err)
	}
	p2 := curves.New(curveType)
	if err := p2.UnmarshalCBOR(tmp.C2); err != nil {
		return fmt.Errorf("failed to unmarshal c2: %w", err)
	}
	ct.C1 = p1
	ct.C2 = p2
	return nil
}

// String returns a string representation of the Ballot.
func (z *Ballot) String() string {
	b, err := json.Marshal(z)
	if b == nil || err != nil {
		return ""
	}
	return string(b)
}

// ToGnark returns z as the struct used by gnark,
// with the points in reduced twisted edwards format
func (z *Ballot) ToGnark() *circuits.Ballot {
	gz := &circuits.Ballot{}
	for i := range z.Ciphertexts {
		gz[i] = *z.Ciphertexts[i].ToGnark()
	}
	return gz
}

// ToGnarkEmulatedBN254 returns z as the struct used by gnark,
// with the points in reduced twisted edwards format
// but as emulated.Element[sw_bn254.ScalarField] instead of frontend.Variable
func (z *Ballot) ToGnarkEmulatedBN254() *circuits.EmulatedBallot[sw_bn254.ScalarField] {
	eb := &circuits.EmulatedBallot[sw_bn254.ScalarField]{}
	for i, z := range z.Ciphertexts {
		c1x, c1y := z.C1.Point()
		c2x, c2y := z.C2.Point()
		eb[i] = circuits.EmulatedCiphertext[sw_bn254.ScalarField]{
			C1: circuits.EmulatedPoint[sw_bn254.ScalarField]{
				X: emulated.ValueOf[sw_bn254.ScalarField](c1x),
				Y: emulated.ValueOf[sw_bn254.ScalarField](c1y),
			},
			C2: circuits.EmulatedPoint[sw_bn254.ScalarField]{
				X: emulated.ValueOf[sw_bn254.ScalarField](c2x),
				Y: emulated.ValueOf[sw_bn254.ScalarField](c2y),
			},
		}
	}
	return eb
}

// Ciphertext represents an ElGamal encrypted message with homomorphic
// properties. It is a wrapper for convenience of the elGamal ciphersystem
// that encapsulates the two points of a ciphertext.
type Ciphertext struct {
	C1 ecc.Point `json:"c1"`
	C2 ecc.Point `json:"c2"`
}

// NewCiphertext creates a new Ciphertext on the same curve as the given Point.
// The Point must be one on of the supported curves by crypto/ecc/curves package,
// can be easily created with curves.New(type)
func NewCiphertext(curve ecc.Point) *Ciphertext {
	return &Ciphertext{C1: curve.New(), C2: curve.New()}
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
	z.C1 = c1
	z.C2 = c2
	return z, nil
}

// Add adds two Ciphertext and stores the result in z, which is also returned.
func (z *Ciphertext) Add(x, y *Ciphertext) *Ciphertext {
	z.C1.SafeAdd(x.C1, y.C1)
	z.C2.SafeAdd(x.C2, y.C2)
	return z
}

// Serialize returns a slice of len 4*32 bytes,
// representing the C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ciphertext) Serialize() []byte {
	var buf bytes.Buffer
	c1x, c1y := z.C1.Point()
	c2x, c2y := z.C2.Point()
	for _, bi := range []*big.Int{c1x, c1y, c2x, c2y} {
		buf.Write(arbo.BigIntToBytes(sizeCoord, bi))
	}
	return buf.Bytes()
}

// Deserialize reconstructs an Ciphertext from a slice of bytes.
// The input must be of len 4*32 bytes (otherwise it returns an error),
// representing the C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ciphertext) Deserialize(data []byte) error {
	// Validate the input length
	if len(data) != sizeCiphertext {
		return fmt.Errorf("invalid input length for Ciphertext: got %d bytes, expected %d bytes", len(data), sizeCiphertext)
	}

	// Helper function to extract *big.Int from a serialized slice
	readBigInt := func(offset int) *big.Int {
		return arbo.BytesToBigInt(data[offset : offset+sizeCoord])
	}
	// Deserialize each field
	z.C1 = z.C1.SetPoint(
		readBigInt(0*sizeCoord),
		readBigInt(1*sizeCoord),
	)
	z.C2 = z.C2.SetPoint(
		readBigInt(2*sizeCoord),
		readBigInt(3*sizeCoord),
	)
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

// ToGnark returns z as the struct used by gnark,
// with the points in reduced twisted edwards format
func (z *Ciphertext) ToGnark() *gelgamal.Ciphertext {
	// TODO: panic if z.C1 or z.C2 is not TE
	c1x, c1y := z.C1.Point()
	c2x, c2y := z.C2.Point()
	return &gelgamal.Ciphertext{
		C1: twistededwards.Point{X: c1x, Y: c1y},
		C2: twistededwards.Point{X: c2x, Y: c2y},
	}
}
