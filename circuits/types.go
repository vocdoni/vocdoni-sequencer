package circuits

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// BallotMode is a struct that contains the common inputs for all the voters.
// The values of this struct should be the same for all the voters in the same
// process. Is a generic struct that can be used with any type of circuit input.
type BallotMode[T any] struct {
	MaxCount        T
	ForceUniqueness T
	MaxValue        T
	MinValue        T
	MaxTotalCost    T
	MinTotalCost    T
	CostExp         T
	CostFromWeight  T
}

func (bm BallotMode[T]) Serialize() []T {
	return []T{
		bm.MaxCount,
		bm.ForceUniqueness,
		bm.MaxValue,
		bm.MinValue,
		bm.MaxTotalCost,
		bm.MinTotalCost,
		bm.CostExp,
		bm.CostFromWeight,
	}
}

// Bytes returns 8*32 bytes representing BallotMode components.
// Returns an empty slice if T is not *big.Int.
func (bm BallotMode[T]) Bytes() []byte {
	bmbi, ok := any(bm).(BallotMode[*big.Int])
	if !ok {
		return []byte{}
	}
	buf := bytes.Buffer{}
	for _, bigint := range bmbi.Serialize() {
		buf.Write(arbo.BigIntToBytes(crypto.SerializedFieldSize, bigint))
	}
	return buf.Bytes()
}

// DeserializeBallotMode reconstructs a BallotMode from a slice of bytes.
// The input must be of len 8*32 bytes (otherwise it returns an error),
// representing 8 big.Ints as little-endian.
func DeserializeBallotMode(data []byte) (BallotMode[*big.Int], error) {
	// Validate the input length
	expectedSize := 8 * crypto.SerializedFieldSize
	if len(data) != expectedSize {
		return BallotMode[*big.Int]{}, fmt.Errorf("invalid input length for BallotMode: got %d bytes, expected %d bytes", len(data), expectedSize)
	}
	// Helper function to extract *big.Int from a serialized slice
	readBigInt := func(offset int) *big.Int {
		return arbo.BytesToBigInt(data[offset : offset+crypto.SerializedFieldSize])
	}
	return BallotMode[*big.Int]{
		MaxCount:        readBigInt(0 * crypto.SerializedFieldSize),
		ForceUniqueness: readBigInt(1 * crypto.SerializedFieldSize),
		MaxValue:        readBigInt(2 * crypto.SerializedFieldSize),
		MinValue:        readBigInt(3 * crypto.SerializedFieldSize),
		MaxTotalCost:    readBigInt(4 * crypto.SerializedFieldSize),
		MinTotalCost:    readBigInt(5 * crypto.SerializedFieldSize),
		CostExp:         readBigInt(6 * crypto.SerializedFieldSize),
		CostFromWeight:  readBigInt(7 * crypto.SerializedFieldSize),
	}, nil
}

func BallotModeFromBM(b types.BallotMode) BallotMode[*big.Int] {
	return BallotMode[*big.Int]{
		MaxCount:        big.NewInt(int64(b.MaxCount)),
		ForceUniqueness: BoolToBigInt(b.ForceUniqueness),
		MaxValue:        b.MaxValue.MathBigInt(),
		MinValue:        b.MinValue.MathBigInt(),
		MaxTotalCost:    b.MaxTotalCost.MathBigInt(),
		MinTotalCost:    b.MinTotalCost.MathBigInt(),
		CostExp:         big.NewInt(int64(b.CostExponent)),
		CostFromWeight:  BoolToBigInt(b.CostFromWeight),
	}
}

type EncryptionKey[T any] struct {
	PubKey [2]T
}

func (k EncryptionKey[T]) Serialize() []T {
	return []T{k.PubKey[0], k.PubKey[1]}
}

// Bytes returns 2*32 bytes representing PubKey components.
// Returns an empty slice if T is not *big.Int.
func (k EncryptionKey[T]) Bytes() []byte {
	ekbi, ok := any(k).(EncryptionKey[*big.Int])
	if !ok {
		return []byte{}
	}
	buf := bytes.Buffer{}
	for _, bigint := range ekbi.Serialize() {
		buf.Write(arbo.BigIntToBytes(crypto.SerializedFieldSize, bigint))
	}
	return buf.Bytes()
}

// AsEmulatedElementBN254 returns the EncryptionKey as a different type.
// Returns an empty EncryptionKey if T is not *big.Int.
func (k EncryptionKey[T]) AsEmulatedElementBN254() EncryptionKey[emulated.Element[sw_bn254.ScalarField]] {
	ekbi, ok := any(k).(EncryptionKey[*big.Int])
	if !ok {
		return EncryptionKey[emulated.Element[sw_bn254.ScalarField]]{}
	}
	return EncryptionKey[emulated.Element[sw_bn254.ScalarField]]{
		[2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](ekbi.PubKey[0]),
			emulated.ValueOf[sw_bn254.ScalarField](ekbi.PubKey[1]),
		},
	}
}

// AsVar returns the EncryptionKey as a different type.
// Returns an empty EncryptionKey if T is not *big.Int.
func (k EncryptionKey[T]) AsVar() EncryptionKey[frontend.Variable] {
	ekbi, ok := any(k).(EncryptionKey[*big.Int])
	if !ok {
		return EncryptionKey[frontend.Variable]{}
	}
	return EncryptionKey[frontend.Variable]{
		[2]frontend.Variable{
			ekbi.PubKey[0],
			ekbi.PubKey[1],
		},
	}
}

// DeserializeEncryptionKey reconstructs a EncryptionKey from a slice of bytes.
// The input must be of len 2*32 bytes (otherwise it returns an error),
// representing 2 big.Ints as little-endian.
func DeserializeEncryptionKey(data []byte) (EncryptionKey[*big.Int], error) {
	// Validate the input length
	expectedSize := 2 * crypto.SerializedFieldSize
	if len(data) != expectedSize {
		return EncryptionKey[*big.Int]{}, fmt.Errorf("invalid input length for EncryptionKey: got %d bytes, expected %d bytes", len(data), expectedSize)
	}
	// Helper function to extract *big.Int from a serialized slice
	readBigInt := func(offset int) *big.Int {
		return arbo.BytesToBigInt(data[offset : offset+crypto.SerializedFieldSize])
	}
	return EncryptionKey[*big.Int]{
		PubKey: [2]*big.Int{
			readBigInt(0 * crypto.SerializedFieldSize),
			readBigInt(1 * crypto.SerializedFieldSize),
		},
	}, nil
}

func EncryptionKeyFromECCPoint(p ecc.Point) EncryptionKey[*big.Int] {
	ekX, ekY := p.Point()
	return EncryptionKey[*big.Int]{PubKey: [2]*big.Int{ekX, ekY}}
}

// Process is a struct that contains the common inputs for a process.
// Is a generic struct that can be used with any type of circuit input.
type Process[T any] struct {
	ID            T
	CensusRoot    T
	BallotMode    BallotMode[T]
	EncryptionKey EncryptionKey[T]
}

func (p Process[T]) Serialize() []T {
	processList := []T{p.ID, p.CensusRoot}
	processList = append(processList, p.EncryptionKey.Serialize()...)
	return append(processList, p.BallotMode.Serialize()...)
}

// Vote is a struct that contains all data related to a vote.
// Is a generic struct that can be used with any type of circuit input.
type Vote[T any] struct {
	Nullifier  T
	Ballot     Ballot
	Address    T
	Commitment T
}

type Ballot [FieldsPerBallot]elgamal.Ciphertext

func NewBallot() *Ballot {
	z := &Ballot{}
	for i := range z {
		z[i] = *elgamal.NewCiphertext()
	}
	return z
}

// Add sets z to the sum x+y and returns z.
//
// Panics if twistededwards curve init fails.
func (z *Ballot) Add(api frontend.API, x, y *Ballot) *Ballot {
	for i := range z {
		z[i].Add(api, &x[i], &y[i])
	}
	return z
}

// AssertIsEqual fails if any of the fields differ between z and x
func (z *Ballot) AssertIsEqual(api frontend.API, x *Ballot) {
	for i := range z {
		z[i].AssertIsEqual(api, &x[i])
	}
}

// Select if b is true, sets z = i1, else z = i2, and returns z
func (z *Ballot) Select(api frontend.API, b frontend.Variable, i1 *Ballot, i2 *Ballot) *Ballot {
	for i := range z {
		z[i] = *z[i].Select(api, b, &i1[i], &i2[i])
	}
	return z
}

// Serialize returns a slice with the C1.X, C1.Y, C2.X, C2.Y in order
func (z *Ballot) Serialize(api frontend.API) []emulated.Element[sw_bn254.ScalarField] {
	vars := []emulated.Element[sw_bn254.ScalarField]{}
	for i := range z {
		for _, zi := range z[i].Serialize() {
			elem, err := utils.UnpackVarToScalar[sw_bn254.ScalarField](api, zi)
			if err != nil {
				panic(err)
			}
			vars = append(vars, *elem)
		}
	}
	return vars
}

// Serialize returns a slice with the C1.X, C1.Y, C2.X, C2.Y in order
func (z *Ballot) SerializeVars() []frontend.Variable {
	vars := []frontend.Variable{}
	for i := range z {
		vars = append(vars, z[i].Serialize()...)
	}
	return vars
}

// EmulatedPoint struct is a copy of the elgamal.Point struct, but using the
// emulated.Element type
type EmulatedPoint[F emulated.FieldParams] struct {
	X, Y emulated.Element[F]
}

// EmulatedCiphertext struct is a copy of the elgamal.Ciphertext struct, but
// using the EmulatedPoint type
type EmulatedCiphertext[F emulated.FieldParams] struct {
	C1, C2 EmulatedPoint[F]
}

// EmulatedBallot is a copy of the Ballot struct, but using the
// EmulatedCiphertext type
type EmulatedBallot[F emulated.FieldParams] [FieldsPerBallot]EmulatedCiphertext[F]

// EmulatedVote is a copy of the Vote struct, but using the emulated.Element
// type as generic type for the Nullifier, Address and Commitment fields, and
// the EmulatedBallot type for the Ballot field.
type EmulatedVote[F emulated.FieldParams] struct {
	Nullifier  emulated.Element[F]
	Ballot     EmulatedBallot[F]
	Address    emulated.Element[F]
	Commitment emulated.Element[F]
}

// NewEmulatedBallot returns a new EmulatedBallot with all fields with both
// points to zero point (0, 1).
func NewEmulatedBallot[F emulated.FieldParams]() *EmulatedBallot[F] {
	field := EmulatedCiphertext[F]{
		C1: EmulatedPoint[F]{X: emulated.ValueOf[F](0), Y: emulated.ValueOf[F](1)},
		C2: EmulatedPoint[F]{X: emulated.ValueOf[F](0), Y: emulated.ValueOf[F](1)},
	}
	z := &EmulatedBallot[F]{}
	for i := range z {
		z[i] = field
	}
	return z
}

// Serialize returns a slice with the C1.X, C1.Y, C2.X, C2.Y in order
func (z *EmulatedBallot[F]) Serialize() []emulated.Element[F] {
	list := []emulated.Element[F]{}
	for _, zi := range z {
		list = append(list,
			zi.C1.X,
			zi.C1.Y,
			zi.C2.X,
			zi.C2.Y)
	}
	return list
}
