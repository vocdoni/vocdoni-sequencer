package curves

import (
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	bjj_gnark "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_gnark"
	bjj_iden3 "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_iden3"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bn254"
)

const (
	CurveTypeBabyJubJub      = "bjj_gnark" // Default bjj curve type
	CurveTypeBabyJubJubGnark = "bjj_gnark"
	CurveTypeBabyJubJubIden3 = "bjj_iden3"
	CurveTypeBN254           = "bn254"
)

// New creates a new instance of a Curve implementation based on the provided type string.
// The supported types are defined as constants in this package.
// If the type is not supported, it will panic.
func New(curveType string) ecc.Point {
	switch curveType {
	case CurveTypeBabyJubJubGnark:
		return &bjj_gnark.BJJ{}
	case CurveTypeBN254:
		return &bn254.G1{}
	case CurveTypeBabyJubJubIden3:
		return &bjj_iden3.BJJ{}
	default:
		panic(fmt.Sprintf("unsupported curve type: %s", curveType))
	}
}
