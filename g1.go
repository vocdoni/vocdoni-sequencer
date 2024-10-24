package main

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var Order = fr.Modulus()

// G1 is the affine representation of a G1 group element.
type G1 struct {
	inner bn254.G1Affine
	lock  sync.Mutex
}

// Add adds two G1 elements and stores the result in the receiver.
func (g *G1) Add(a, b *G1) {
	g.inner.Add(&a.inner, &b.inner)
}

// SafeAdd adds two G1 elements and stores the result in the receiver.
// It is thread-safe.
func (g *G1) SafeAdd(a, b *G1) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.inner.Add(&a.inner, &b.inner)
}

// ScalarMult performs scalar multiplication of a G1 element.
func (g *G1) ScalarMult(a *G1, scalar *big.Int) {
	g.inner.ScalarMultiplication(&a.inner, scalar)
}

// ScalarBaseMult performs scalar multiplication of the generator point.
func (g *G1) ScalarBaseMult(scalar *big.Int) {
	g.inner.ScalarMultiplicationBase(scalar)
}

// Marshal serializes the G1 element into a byte slice.
func (g *G1) Marshal() []byte {
	return g.inner.Marshal()
}

// Unmarshal deserializes a byte slice into a G1 element.
func (g *G1) Unmarshal(buf []byte) error {
	_, err := g.inner.SetBytes(buf)
	return err
}

// Equal checks if two G1 elements are equal.
func (g *G1) Equal(a *G1) bool {
	return g.inner.Equal(&a.inner)
}

// Neg negates a G1 element.
func (g *G1) Neg(a *G1) {
	g.inner.Neg(&a.inner)
}

// SetZero sets the G1 element to the zero value (point at infinity).
func (g *G1) SetZero() {
	g.inner.X.SetZero()
	g.inner.Y.SetZero()
}

func (g *G1) String() string {
	bytes := g.Marshal()
	return fmt.Sprintf("%x", bytes)
}
