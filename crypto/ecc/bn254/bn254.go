package bn254

import (
	"fmt"
	"math/big"
	"sync"

	curve "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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
