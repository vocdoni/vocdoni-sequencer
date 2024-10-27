package bjj

import (
	"fmt"
	"math/big"
	"sync"

	babyjubjub "github.com/iden3/go-iden3-crypto/babyjub"

	curve "github.com/vocdoni/elGamal-sandbox/ecc"
)

// BJJ is the affine representation of the BabyJubJub group element.
type BJJ struct {
	inner *babyjubjub.Point
	lock  sync.Mutex
}

// New creates a new BJJ point (identity element by default).
func New() curve.Point {
	return &BJJ{inner: babyjubjub.NewPoint()}
}

func (g *BJJ) New() curve.Point {
	return &BJJ{inner: babyjubjub.NewPoint()}
}

func (g *BJJ) Order() *big.Int {
	return babyjubjub.SubOrder
}

func (g *BJJ) Add(a, b curve.Point) {
	g.inner = g.inner.Projective().Add(a.(*BJJ).inner.Projective(), b.(*BJJ).inner.Projective()).Affine()
}

func (g *BJJ) SafeAdd(a, b curve.Point) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.Add(a, b)
}

func (g *BJJ) ScalarMult(a curve.Point, scalar *big.Int) {
	g.inner = g.inner.Mul(scalar, a.(*BJJ).inner)
}

func (g *BJJ) ScalarBaseMult(scalar *big.Int) {
	g.inner = g.inner.Mul(scalar, babyjubjub.B8)
}

func (g *BJJ) Marshal() []byte {
	b := g.inner.Compress()
	return b[:]
}

func (g *BJJ) Unmarshal(buf []byte) error {
	b32 := [32]byte{}
	copy(b32[:], buf)
	_, err := g.inner.Decompress(b32)
	return err
}

func (g *BJJ) Equal(a curve.Point) bool {
	return g.inner.X.Cmp(a.(*BJJ).inner.X) == 0 && g.inner.Y.Cmp(a.(*BJJ).inner.Y) == 0
}

func (g *BJJ) Neg(a curve.Point) {
	proj := g.inner.Projective()
	proj.X = proj.X.Neg(proj.X)
	g.inner.X = g.inner.X.Set(proj.Affine().X)
	//g.inner.X = g.inner.X.Neg(g.inner.X) // Negate the x-coordinate
	//g.inner.X = g.inner.X.Mod(g.inner.X, constants.Q)
}

func (g *BJJ) SetZero() {
	p := g.inner.Projective()
	p.X.SetZero() // Set X to 0
	p.Y.SetOne()  // Set Y to 1
	p.Z.SetOne()  // Set Z to 1
	g.inner = p.Affine()
}

func (g *BJJ) Set(a curve.Point) {
	g.inner.X = g.inner.X.Set(a.(*BJJ).inner.X)
	g.inner.Y = g.inner.Y.Set(a.(*BJJ).inner.Y)
}

func (g *BJJ) SetGenerator() {
	gen := babyjubjub.B8
	g.inner.X = g.inner.X.Set(gen.X)
	g.inner.Y = g.inner.Y.Set(gen.Y)
}

func (g *BJJ) String() string {
	//bytes := g.Marshal()
	//return fmt.Sprintf("%x", bytes)
	return fmt.Sprintf("%s,%s", g.inner.X.String(), g.inner.Y.String())
}
