package curves

import (
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/ecc"
	bjj_gnark "github.com/vocdoni/vocdoni-z-sandbox/ecc/bjj_gnark"
	bjj_iden3 "github.com/vocdoni/vocdoni-z-sandbox/ecc/bjj_iden3"
	"github.com/vocdoni/vocdoni-z-sandbox/ecc/bn254"
)

const (
	CurveTypeBabyJubJub      = "bjj_gnark" // Default bjj curve type
	CurveTypeBabyJubJubGnark = "bjj_gnark"
	CurveTypeBabyJubJubIden3 = "bjj_iden3"
	CurveTypeBN254           = "bn254"
)

// New creates a new instance of a Curve implementation based on the provided type string.
// The supported types are defined as constants in this package.
func New(curveType string) (ecc.Point, error) {
	switch curveType {
	case CurveTypeBabyJubJubGnark:
		return &bjj_gnark.BJJ{}, nil
	case CurveTypeBN254:
		return &bn254.G1{}, nil
	case CurveTypeBabyJubJubIden3:
		return &bjj_iden3.BJJ{}, nil
	default:
		return nil, fmt.Errorf("unsupported curve type: %s", curveType)
	}
}
