package bjj

import (
	"fmt"
	"math/big"
	"sync"

	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	curve "github.com/vocdoni/elGamal-sandbox/ecc"
)

var Params babyjubjub.CurveParams

func init() {
	Params = babyjubjub.GetEdwardsCurve()
}

// BJJ is the affine representation of the BabyJubJub group element.
type BJJ struct {
	inner *babyjubjub.PointAffine
	lock  sync.Mutex
}

func (g *BJJ) New() curve.Point {
	return &BJJ{inner: new(babyjubjub.PointAffine)}
}

func (g *BJJ) Order() *big.Int {
	order := babyjubjub.GetEdwardsCurve().Order
	return &order
}

func (g *BJJ) Add(a, b curve.Point) {
	g.inner.Add(a.(*BJJ).inner, b.(*BJJ).inner)
}

func (g *BJJ) SafeAdd(a, b curve.Point) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.inner.Add(a.(*BJJ).inner, b.(*BJJ).inner)
}

func (g *BJJ) ScalarMult(a curve.Point, scalar *big.Int) {
	g.inner.ScalarMultiplication(a.(*BJJ).inner, scalar)
}

func (g *BJJ) ScalarBaseMult(scalar *big.Int) {
	g.inner.ScalarMultiplication(&Params.Base, scalar)
}

func (g *BJJ) Marshal() []byte {
	return g.inner.Marshal()
}

func (g *BJJ) Unmarshal(buf []byte) error {
	_, err := g.inner.SetBytes(buf)
	return err
}

func (g *BJJ) Equal(a curve.Point) bool {
	return g.inner.Equal(a.(*BJJ).inner)
}

func (g *BJJ) Neg(a curve.Point) {
	g.inner.Neg(a.(*BJJ).inner)
}

func (g *BJJ) SetZero() {
	g.inner.X.SetZero()
	g.inner.Y.SetZero()
}

func (g *BJJ) Set(a curve.Point) {
	g.inner.X.Set(&a.(*BJJ).inner.X)
	g.inner.Y.Set(&a.(*BJJ).inner.Y)
}

func (g *BJJ) SetGenerator() {
	gen := Params.Base
	g.inner.X.Set(&gen.X)
	g.inner.Y.Set(&gen.Y)
}

func (g *BJJ) String() string {
	bytes := g.Marshal()
	return fmt.Sprintf("%x", bytes)
}
