package bjj

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	curve "github.com/vocdoni/elGamal-sandbox/ecc"
)

var Params babyjubjub.CurveParams

// BJJ is the affine representation of the BabyJubJub group element.
type BJJ struct {
	inner *babyjubjub.PointAffine
	lock  sync.Mutex
}

// Scaling factor f (as big.Int)
var scalingFactor *big.Int

func init() {
	Params = babyjubjub.GetEdwardsCurve()
	scalingFactor = new(big.Int)
	scalingFactor.SetString("6360561867910373094066688120553762416144456282423235903351243436111059670888", 10)
}

// New creates a new BJJ point (identity element by default).
func New() curve.Point {
	return &BJJ{inner: new(babyjubjub.PointAffine)}
}

// New creates a new BJJ point (identity element by default).
func (g *BJJ) New() curve.Point {
	p := &BJJ{inner: new(babyjubjub.PointAffine)}
	p.SetZero()
	return p
}

// Order returns the order of the BabyJubJub curve subgroup.
func (g *BJJ) Order() *big.Int {
	return new(big.Int).Set(&Params.Order)
}

// Add performs the addition of two points and stores the result in g.
func (g *BJJ) Add(a, b curve.Point) {
	g.inner.Add(a.(*BJJ).inner, b.(*BJJ).inner)
}

// SafeAdd performs the addition of two points with a lock.
func (g *BJJ) SafeAdd(a, b curve.Point) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.Add(a, b)
}

// ScalarMult performs scalar multiplication of a point by a scalar.
func (g *BJJ) ScalarMult(a curve.Point, scalar *big.Int) {
	g.inner.ScalarMultiplication(a.(*BJJ).inner, scalar)
}

// ScalarBaseMult performs scalar multiplication using the base point.
func (g *BJJ) ScalarBaseMult(scalar *big.Int) {
	g.SetGenerator()
	g.ScalarMult(g, scalar)
}

// Equal checks if the given point is equal to the current point.
func (g *BJJ) Equal(a curve.Point) bool {
	return g.inner.Equal(a.(*BJJ).inner)
}

// Neg negates the given point and stores the result in g.
func (g *BJJ) Neg(a curve.Point) {
	g.inner.Neg(a.(*BJJ).inner)
}

// SetZero sets the current point to the identity element (0, 1).
func (g *BJJ) SetZero() {
	g.inner.X.SetZero() // X = 0
	g.inner.Y.SetOne()  // Y = 1
}

// Set sets g to the value of another point.
func (g *BJJ) Set(a curve.Point) {
	g.inner.Set(a.(*BJJ).inner)
}

// SetGenerator sets the point to the BabyJubJub generator.
func (g *BJJ) SetGenerator() {
	g.inner.Set(&Params.Base)
}

// String returns a string representation of the point in Twisted Edwards coordinates.
func (g *BJJ) String() string {
	xTE, yTE := g.toTwistedEdwards()
	return fmt.Sprintf("%s,%s", xTE.String(), yTE.String())
}

// Marshal serializes the elliptic curve element into a byte slice.
func (p *BJJ) Marshal() []byte {
	return p.inner.Marshal()
}

// Unmarshal deserializes the elliptic curve element from a byte slice.
func (p *BJJ) Unmarshal(buf []byte) error {
	return p.inner.Unmarshal(buf)
}

// Convert RTE x' to TE x by dividing by -f
// see https://github.com/bellesmarta/baby_jubjub
// Gnark uses the reduced twisted Edwards formula while iden3 uses the standard twisted Edwards formula.
func (g *BJJ) toTwistedEdwards() (*big.Int, *big.Int) {
	// Step 1: Convert scalingFactor to fr.Element (mod p)
	var f fr.Element
	f.SetBigInt(scalingFactor) // f = scalingFactor mod p

	// Step 2: Compute negF = -f mod p
	var negF fr.Element
	negF.Neg(&f) // negF = -f mod p

	// Step 3: Compute the inverse of negF in the field
	var negFInv fr.Element
	negFInv.Inverse(&negF) // negFInv = (-f)^{-1} mod p

	// Step 4: Multiply g.inner.X by negFInv to get xTE
	var xTE fr.Element
	xTE.Mul(&g.inner.X, &negFInv) // xTE = g.inner.X * negFInv mod p

	// Step 5: Convert xTE and g.inner.Y to *big.Int
	xTEBigInt := new(big.Int)
	yTEBigInt := new(big.Int)
	xTE.BigInt(xTEBigInt)
	g.inner.Y.BigInt(yTEBigInt)

	return xTEBigInt, yTEBigInt
}
