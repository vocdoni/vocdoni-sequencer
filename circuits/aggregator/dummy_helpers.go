package aggregator

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func NBits(bits int) *big.Int {
	// no valid number if bits <= 0
	if bits <= 0 {
		return big.NewInt(0)
	}
	// compute (1 << bits) - 1
	maxNum := big.NewInt(1)
	// left shift by 'bits'
	maxNum.Lsh(maxNum, uint(bits))
	// subtract 1 to get all bits set to 1
	return maxNum.Sub(maxNum, big.NewInt(1))
}

func fillToN(inputs []*big.Int, n int) []*big.Int {
	for i := 0; i < n; i++ {
		if i >= len(inputs) {
			inputs = append(inputs, big.NewInt(0))
		} else if inputs[i] == nil {
			inputs[i] = big.NewInt(0)
		}
	}
	return inputs
}

func compileCircuit(placeholder, assigment frontend.Circuit, outer *big.Int, field *big.Int) (constraint.ConstraintSystem, witness.Witness, groth16.Proof, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, placeholder)
	if err != nil {
		fmt.Printf("compilation: %v\n", err)
		return nil, nil, nil, nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("setup: %v\n", err)
		return nil, nil, nil, nil, err
	}
	fullWitness, err := frontend.NewWitness(assigment, field)
	if err != nil {
		fmt.Printf("witness parse: %v\n", err)
		return nil, nil, nil, nil, err
	}
	proof, err := groth16.Prove(ccs, pk, fullWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		fmt.Printf("proving: %v\n", err)
		return nil, nil, nil, nil, err
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		fmt.Printf("getting public witnesss: %v\n", err)
		return nil, nil, nil, nil, err
	}
	if err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(outer, field)); err != nil {
		fmt.Printf("verifying: %v\n", err)
		return nil, nil, nil, nil, err
	}
	return ccs, publicWitness, proof, vk, nil
}

func fillWithDummyValues(w AggregatorCircuit, main constraint.ConstraintSystem, nVotes int) (AggregatorCircuit, constraint.ConstraintSystem, stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT], error) {
	dummyCCS, pubWitness, proof, vk, err := compileCircuit(DummyPlaceholder(main), DummyAssigment(), ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	if err != nil {
		return AggregatorCircuit{}, nil, stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, err
	}
	dummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		return AggregatorCircuit{}, nil, stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, err
	}
	dummyWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	if err != nil {
		return AggregatorCircuit{}, nil, stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, err
	}
	dummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return AggregatorCircuit{}, nil, stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, err
	}
	dummyValue := frontend.Variable(0)
	var dummyEncryptedBallots [MaxFields][2][2]frontend.Variable
	for i := 0; i < MaxFields; i++ {
		dummyEncryptedBallots[i] = [2][2]frontend.Variable{
			{dummyValue, dummyValue}, {dummyValue, dummyValue},
		}
	}
	for i := nVotes; i < MaxVotes; i++ {
		w.Nullifiers[i] = dummyValue
		w.Commitments[i] = dummyValue
		w.Addresses[i] = dummyValue
		w.EncryptedBallots[i] = dummyEncryptedBallots
		w.VerifyProofs[i] = dummyProof
		w.VerifyPublicInputs[i] = dummyWitness
	}
	return w, dummyCCS, dummyVk, nil
}
