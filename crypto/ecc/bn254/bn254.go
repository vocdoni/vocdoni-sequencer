package bn254

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/fxamacker/cbor/v2"
	curve "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/types"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const CurveType = "bn254"

var Generator bn254.G1Jac

func init() {
	Generator.X.SetOne()
	Generator.Y.SetUint64(2)
	Generator.Z.SetOne()
}

// G1 is the affine representation of a G1 group element.
type G1 struct {
	inner *bn254.G1Affine
	lock  sync.Mutex
}

func (g *G1) New() curve.Point {
	return &G1{inner: new(bn254.G1Affine)}
}

func (g *G1) Order() *big.Int {
	return fr.Modulus()
}

func (g *G1) Add(a, b curve.Point) {
	temp := new(bn254.G1Affine)
	temp.Add(a.(*G1).inner, b.(*G1).inner)
	*g.inner = *temp
}

func (g *G1) SafeAdd(a, b curve.Point) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.inner.Add(a.(*G1).inner, b.(*G1).inner)
}

func (g *G1) ScalarMult(a curve.Point, scalar *big.Int) {
	temp := new(bn254.G1Affine)
	temp.ScalarMultiplication(a.(*G1).inner, scalar)
	*g.inner = *temp
}

func (g *G1) ScalarBaseMult(scalar *big.Int) {
	g.inner.ScalarMultiplicationBase(scalar)
}

func (g *G1) Marshal() []byte {
	return g.inner.Marshal()
}

func (g *G1) Unmarshal(buf []byte) error {
	_, err := g.inner.SetBytes(buf)
	return err
}

func (g *G1) MarshalJSON() ([]byte, error) {
	x := types.BigInt(*g.inner.X.BigInt(new(big.Int)))
	y := types.BigInt(*g.inner.Y.BigInt(new(big.Int)))
	return json.Marshal([]types.BigInt{x, y})
}

func (g *G1) UnmarshalJSON(buf []byte) error {
	if g.inner == nil {
		g.inner = new(bn254.G1Affine)
	}
	var coords []types.BigInt
	if err := json.Unmarshal(buf, &coords); err != nil {
		return err
	}
	if len(coords) != 2 {
		return fmt.Errorf("expected 2 coordinates, got %d", len(coords))
	}
	g.inner.X.SetBigInt(coords[0].MathBigInt())
	g.inner.Y.SetBigInt(coords[1].MathBigInt())
	return nil
}

func (g *G1) MarshalCBOR() ([]byte, error) {
	x := g.inner.X.BigInt(new(big.Int))
	y := g.inner.Y.BigInt(new(big.Int))
	return cbor.Marshal([]*big.Int{x, y})
}

func (g *G1) UnmarshalCBOR(buf []byte) error {
	if g.inner == nil {
		g.inner = new(bn254.G1Affine)
	}
	var coords []*big.Int
	if err := cbor.Unmarshal(buf, &coords); err != nil {
		return err
	}
	if len(coords) != 2 {
		return fmt.Errorf("expected 2 coordinates, got %d", len(coords))
	}
	g.inner.X.SetBigInt(coords[0])
	g.inner.Y.SetBigInt(coords[1])
	return nil
}

func (g *G1) Equal(a curve.Point) bool {
	return g.inner.Equal(a.(*G1).inner)
}

func (g *G1) Neg(a curve.Point) {
	g.inner.Neg(a.(*G1).inner)
}

func (g *G1) SetZero() {
	g.inner.X.SetZero()
	g.inner.Y.SetZero()
}

func (g *G1) Set(a curve.Point) {
	g.inner.X.Set(&a.(*G1).inner.X)
	g.inner.Y.Set(&a.(*G1).inner.Y)
}

func (g *G1) SetGenerator() {
	g.inner.FromJacobian(&Generator)
}

func (g *G1) String() string {
	bytes := g.Marshal()
	return fmt.Sprintf("%x", bytes)
}

func (g *G1) Point() (*big.Int, *big.Int) {
	return g.inner.X.BigInt(new(big.Int)), g.inner.Y.BigInt(new(big.Int))
}

func (g *G1) SetPoint(x, y *big.Int) curve.Point {
	g = &G1{inner: new(bn254.G1Affine)}
	g.inner.X.SetBigInt(x)
	g.inner.Y.SetBigInt(y)
	return g
}

func (g *G1) Type() string {
	return CurveType
}
