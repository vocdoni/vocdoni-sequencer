package aggregator

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
)

// EncodeProofsSelector function returns a number that its base2 representation
// contains the first nValidProofs bits set to one. It allows to encode the
// number of valid proofs as selector to switch between main circuit vk and the
// dummy one.
func EncodeProofsSelector(nValidProofs int) *big.Int {
	// no valid number if nValidProofs <= 0
	if nValidProofs <= 0 {
		return big.NewInt(0)
	}
	// (1 << nValidProofs) - 1 gives a binary number with nValidProofs ones
	// compute (1 << n) - 1
	maxNum := big.NewInt(1)
	// left shift by 'n'
	maxNum.Lsh(maxNum, uint(nValidProofs))
	// subtract 1 to get all n set to 1
	return maxNum.Sub(maxNum, big.NewInt(1))
}

// VectorToEmulatedElements function converts a backend.Witness vector to an
// array of emulated.Element[T] elements. A witness vector is a list of uints
// that represents every limb of a list of variables of the flattened witness.
// This function group the limbs in groups of T.NbLimbs() to create each element
// of the array. Returns an error if the conversion fails or the vector type is
// not supported.
func VectorToEmulatedElements[T emulated.FieldParams](v any) ([]emulated.Element[T], error) {
	var fr T
	nbLimbs := int(fr.NbLimbs())

	// Helper function to process each vector type
	processVector := func(vectorLen int, getLimbs func(i int) frontend.Variable) []emulated.Element[T] {
		// Calculate the number of emulated.Elements needed (ceiling division)
		numElements := (vectorLen + nbLimbs - 1) / nbLimbs
		elements := make([]emulated.Element[T], numElements)

		for elemIdx := 0; elemIdx < numElements; elemIdx++ {
			limbs := make([]frontend.Variable, nbLimbs)
			for limbIdx := 0; limbIdx < nbLimbs; limbIdx++ {
				globalIdx := elemIdx*nbLimbs + limbIdx
				if globalIdx < vectorLen {
					limbs[limbIdx] = getLimbs(globalIdx)
				} else {
					// Pad with zero if there are not enough elements
					limbs[limbIdx] = frontend.Variable(big.NewInt(0))
				}
			}
			elements[elemIdx] = emulated.Element[T]{Limbs: limbs}
		}
		return elements
	}

	switch pv := v.(type) {
	case fr_bn254.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bls12377.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bls12381.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bw6761.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bls24317.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bls24315.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	case fr_bw6633.Vector:
		return processVector(len(pv), func(i int) frontend.Variable {
			return pv[i].BigInt(new(big.Int))
		}), nil
	default:
		return nil, errors.New("unsupported vector type")
	}
}

// FillWithDummyFixed function fills the placeholder and the assigments
// provided with a dummy circuit stuff and proofs compiled for the main
// constraint.ConstraintSystem provided. It starts to fill from the index
// provided and fixes the dummy verification key. Returns an error if
// something fails.
func FillWithDummyFixed(placeholder, assigments AggregatorCircuit, main constraint.ConstraintSystem, fromIdx int) (
	AggregatorCircuit, AggregatorCircuit, error,
) {
	dummyCCS, pubWitness, proof, vk, err := dummy.Prove(
		dummy.Placeholder(main), dummy.Assignment(1),
		ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, err
	}
	// set fixed dummy vk in the placeholders
	placeholder.DummyVerificationKey, err = stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, fmt.Errorf("fix dummy vk error: %w", err)
	}
	// parse dummy proof and witness
	dummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, fmt.Errorf("dummy proof value error: %w", err)
	}
	dummyWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, fmt.Errorf("dummy witness value error: %w", err)
	}
	// set some dummy values in others assigments variables
	dummyValue := emulated.ValueOf[sw_bn254.ScalarField](0)
	var dummyEncryptedBallots [MaxFields][2][2]emulated.Element[sw_bn254.ScalarField]
	for i := 0; i < MaxFields; i++ {
		dummyEncryptedBallots[i] = [2][2]emulated.Element[sw_bn254.ScalarField]{
			{dummyValue, dummyValue}, {dummyValue, dummyValue},
		}
	}
	// fill placeholders and assigments dummy values
	for i := range assigments.Proofs {
		placeholder.Proofs[i].Proof = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		placeholder.Proofs[i].Witness = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
		if i >= fromIdx {
			assigments.Nullifiers[i] = dummyValue
			assigments.Commitments[i] = dummyValue
			assigments.Addresses[i] = dummyValue
			assigments.EncryptedBallots[i] = dummyEncryptedBallots
			assigments.Proofs[i].Proof = dummyProof
			assigments.Proofs[i].Witness = dummyWitness
		}
	}
	return placeholder, assigments, nil
}
