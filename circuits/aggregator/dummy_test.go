package aggregator

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	circomtest "github.com/vocdoni/vocdoni-z-sandbox/circuits/circom"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

func TestDummyCircuit(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &DummyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	dummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(dummyVk.G1.K))
	t.Log(len(dummyVk.CommitmentKeys))
}

func TestAggregator(t *testing.T) {
	// compile ballot verifier circuit
	ballotVerifierPlaceholder, err := circomtest.Circom2GnarkPlaceholder()
	if err != nil {
		t.Fatal(err)
	}
	// compile vote verifier circuit
	voteVerifierPlaceholder := &voteverifier.VerifyVoteCircuit{
		CircomProof:            ballotVerifierPlaceholder.Proof,
		CircomPublicInputsHash: ballotVerifierPlaceholder.Witness,
		CircomVerificationKey:  ballotVerifierPlaceholder.Vk,
	}
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, voteVerifierPlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		t.Fatal(err)
	}
	dummyCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &DummyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	_, dummyVk, err := groth16.Setup(dummyCCS)
	if err != nil {
		t.Fatal(err)
	}
	fixedDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	if err != nil {
		t.Fatal(err)
	}
	finalPlaceholder := AggregatorCircuit{
		VerifyProofs:       [MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		VerifyPublicInputs: [MaxVotes]stdgroth16.Witness[sw_bls12377.ScalarField]{},
		VerificationKey: VerfiyingAndDummyKey{
			Vk:    fixedVk,
			Dummy: fixedDummyVk,
		},
	}
	for i := 0; i < MaxVotes; i++ {
		if i < nVotes {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](ccs)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs)
		} else {
			finalPlaceholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
			finalPlaceholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
		}
	}
	finalCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &finalPlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	_, finalVk, err := groth16.Setup(finalCCS)
	if err != nil {
		t.Fatal(err)
	}
	fixedFinalVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](finalVk)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(len(fixedFinalVk.G1.K))
	t.Log(len(fixedFinalVk.CommitmentKeys))
}
