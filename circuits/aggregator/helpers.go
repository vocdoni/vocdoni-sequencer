package aggregator

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
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

func RecursiveDummy(main constraint.ConstraintSystem, persist bool) (
	constraint.ConstraintSystem,
	stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT],
	stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	stdgroth16.Witness[sw_bls12377.ScalarField],
	error,
) {
	nilVk := stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}
	nilProof := stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	nilWitness := stdgroth16.Witness[sw_bls12377.ScalarField]{}

	dummyCCS, pubWitness, proof, vk, err := dummy.Prove(
		dummy.Placeholder(main), dummy.Assignment(1),
		ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField(), persist)
	if err != nil {
		return nil, nilVk, nilProof, nilWitness, err
	}
	// set fixed dummy vk in the placeholders
	dummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return nil, nilVk, nilProof, nilWitness, fmt.Errorf("fix dummy vk error: %w", err)
	}
	// parse dummy proof and witness
	dummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		return nil, nilVk, nilProof, nilWitness, fmt.Errorf("dummy proof value error: %w", err)
	}
	dummyWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	if err != nil {
		return nil, nilVk, nilProof, nilWitness, fmt.Errorf("dummy witness value error: %w", err)
	}
	return dummyCCS, dummyVk, dummyProof, dummyWitness, nil
}

// FillWithDummyFixed function fills the placeholder and the assigments
// provided with a dummy circuit stuff and proofs compiled for the main
// constraint.ConstraintSystem provided. It starts to fill from the index
// provided and fixes the dummy verification key. Returns an error if
// something fails.
func FillWithDummyFixed(placeholder, assigments AggregatorCircuit, main constraint.ConstraintSystem, fromIdx int, persist bool) (
	AggregatorCircuit, AggregatorCircuit, error,
) {
	dummyCCS, dummyVk, dummyProof, _, err := RecursiveDummy(main, persist)
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, err
	}
	// set fixed dummy vk in the placeholders
	placeholder.DummyVerificationKey = dummyVk
	// set some dummy values in others assigments variables
	dummyValue := emulated.ValueOf[sw_bn254.ScalarField](0)
	// fill placeholders and assigments dummy values
	for i := range assigments.Proofs {
		placeholder.Proofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		if i >= fromIdx {
			assigments.Votes[i].Nullifier = dummyValue
			assigments.Votes[i].Commitment = dummyValue
			assigments.Votes[i].Address = dummyValue
			assigments.Votes[i].Ballot = *circuits.NewEmulatedBallot[sw_bn254.ScalarField]()
			assigments.Proofs[i] = dummyProof
		}
	}
	return placeholder, assigments, nil
}
