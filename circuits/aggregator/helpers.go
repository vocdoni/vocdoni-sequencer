package aggregator

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
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

func RecursiveDummy(main constraint.ConstraintSystem, persist bool, srs, srsLagrange kzg.SRS) (
	constraint.ConstraintSystem,
	stdplonk.BaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	stdplonk.CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine],
	stdplonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	stdplonk.Witness[sw_bls12377.ScalarField],
	error,
) {
	nilBaseVk := stdplonk.BaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	nilVk := stdplonk.CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{}
	nilProof := stdplonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	nilWitness := stdplonk.Witness[sw_bls12377.ScalarField]{}

	dummyCCS, pubWitness, proof, vk, err := dummy.Prove(
		dummy.Placeholder(main), dummy.Assignment(1),
		circuits.AggregatorCurve.ScalarField(), circuits.VoteVerifierCurve.ScalarField(), persist, srs, srsLagrange)
	if err != nil {
		return nil, nilBaseVk, nilVk, nilProof, nilWitness, err
	}
	// set fixed dummy vk in the placeholders
	baseDummyVk, err := stdplonk.ValueOfBaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](vk)
	if err != nil {
		return nil, nilBaseVk, nilVk, nilProof, nilWitness, fmt.Errorf("fix base dummy vk error: %w", err)
	}
	dummyVk, err := stdplonk.ValueOfCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](vk)
	if err != nil {
		return nil, nilBaseVk, nilVk, nilProof, nilWitness, fmt.Errorf("fix dummy vk error: %w", err)
	}
	// parse dummy proof and witness
	dummyProof, err := stdplonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		return nil, nilBaseVk, nilVk, nilProof, nilWitness, fmt.Errorf("dummy proof value error: %w", err)
	}
	dummyWitness, err := stdplonk.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	if err != nil {
		return nil, nilBaseVk, nilVk, nilProof, nilWitness, fmt.Errorf("dummy witness value error: %w", err)
	}
	return dummyCCS, baseDummyVk, dummyVk, dummyProof, dummyWitness, nil
}

// FillWithDummyFixed function fills the placeholder and the assignments
// provided with a dummy circuit stuff and proofs compiled for the main
// constraint.ConstraintSystem provided. It starts to fill from the index
// provided and fixes the dummy verification key. Returns an error if
// something fails.
func FillWithDummyFixed(placeholder, assignments AggregatorCircuit, main constraint.ConstraintSystem, fromIdx int, persist bool, srs, srsLagrange kzg.SRS) (
	AggregatorCircuit, AggregatorCircuit, error,
) {
	dummyCCS, _, dummyVk, dummyProof, _, err := RecursiveDummy(main, persist, srs, srsLagrange)
	if err != nil {
		return AggregatorCircuit{}, AggregatorCircuit{}, err
	}
	// set fixed dummy vk in the placeholders
	placeholder.DummyVerificationKey = dummyVk
	// set some dummy values in others assignments variables
	dummyValue := emulated.ValueOf[sw_bn254.ScalarField](0)
	// fill placeholders and assignments dummy values
	for i := range assignments.Proofs {
		placeholder.Proofs[i] = stdplonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		if i >= fromIdx {
			assignments.Votes[i].Nullifier = dummyValue
			assignments.Votes[i].Commitment = dummyValue
			assignments.Votes[i].Address = dummyValue
			assignments.Votes[i].Ballot = *circuits.NewEmulatedBallot[sw_bn254.ScalarField]()
			assignments.Proofs[i] = dummyProof
		}
	}
	return placeholder, assignments, nil
}
