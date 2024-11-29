package voteverifier

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
)

// nativeMiMCHashFn is a hash function that hashes the data provided using the
// mimc hash function and the current compiler field. It is used to hash the
// leaves of the census tree during the proof verification.
func nativeMiMCHashFn(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, err
	}
	h.Write(data...)
	return h.Sum(), nil
}

// packScalarToVar converts a scalar element to a frontend.Variable. This is
// used to convert the scalar elements of a field to frontend.Variable to be
// used in the circuit. The resulting frontend.Variable will be packed with
// in the field of the circuit compiler, so it should be used with care.
func packScalarToVar[S emulated.FieldParams](api frontend.API, s *emulated.Element[S]) (frontend.Variable, error) {
	var fr S
	field, err := emulated.NewField[S](api)
	if err != nil {
		return nil, err
	}
	reduced := field.Reduce(s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = api.Add(res, api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res, nil
}
