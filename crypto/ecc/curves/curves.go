package curves

import (
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	bjj_gnark "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_gnark"
	bjj_iden3 "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_iden3"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bn254"
)

// New creates a new instance of a Curve implementation based on the provided type string.
// The supported types are defined as constants in this package.
// If the type is not supported, it will panic.
func New(curveType string) ecc.Point {
	switch curveType {
	case bjj_gnark.CurveType:
		return &bjj_gnark.BJJ{}
	case bn254.CurveType:
		return &bn254.G1{}
	case bjj_iden3.CurveType:
		return &bjj_iden3.BJJ{}
	default:
		panic(fmt.Sprintf("unsupported curve type: %s", curveType))
	}
}

// Curves returns a list of supported curve types.
func Curves() []string {
	return []string{
		bjj_gnark.CurveType,
		bn254.CurveType,
		bjj_iden3.CurveType,
	}
}
