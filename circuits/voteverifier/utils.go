package voteverifier

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
)

// censusHashFn is a hash function that hashes the data provided using the
// mimc hash function and the current compiler field. It is used to hash the
// leaves of the census tree during the proof verification.
func censusHashFn(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, err
	}
	h.Write(data...)
	return h.Sum(), nil
}

func circomHashFn(api frontend.API, expected emulated.Element[sw_bn254.ScalarField], data ...emulated.Element[sw_bn254.ScalarField]) error {
	h, err := mimc7.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(data...)
	h.AssertSumIsEqual(expected)
	return nil
}

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
