package aggregator

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	circomtest "github.com/vocdoni/vocdoni-z-sandbox/circuits/circom"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

type OutterCircuit struct {
	Proof           stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs    stdgroth16.Witness[sw_bls12377.ScalarField]
	VerificationKey stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

func (c *OutterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}
	if err := verifier.AssertProof(c.VerificationKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic()); err != nil {
		return err
	}
	return nil
}

func TestDummyCircuit(t *testing.T) {
	c := qt.New(t)
	dummyCCS, dummyPubWitness, dummyProof, dummyVk, err := prepareDummy(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	c.Assert(err, qt.IsNil)

	proofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
	proof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyProof)
	c.Assert(err, qt.IsNil)

	pubWitnessPlaceholder := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
	pubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](dummyPubWitness)
	c.Assert(err, qt.IsNil)

	vk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	c.Assert(err, qt.IsNil)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&OutterCircuit{
		Proof:           proofPlaceholder,
		PublicInputs:    pubWitnessPlaceholder,
		VerificationKey: vk,
	}, &OutterCircuit{
		Proof:        proof,
		PublicInputs: pubWitness,
	}, test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}

func TestDummyCircuitInfo(t *testing.T) {
	c := qt.New(t)
	// main circuit
	ballotVerifierPlaceholder, err := circomtest.Circom2GnarkPlaceholder()
	c.Assert(err, qt.IsNil)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomProof:            ballotVerifierPlaceholder.Proof,
		CircomPublicInputsHash: ballotVerifierPlaceholder.Witness,
		CircomVerificationKey:  ballotVerifierPlaceholder.Vk,
	})
	c.Assert(err, qt.IsNil)
	vk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](ccs)
	// dummy circuit
	dummyCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &DummyCircuit{})
	c.Assert(err, qt.IsNil)
	dummyVk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyCCS)
	// check same K and CommitmentKeys length
	c.Assert(dummyVk.G1.K, qt.HasLen, len(vk.G1.K))
	c.Assert(dummyVk.CommitmentKeys, qt.HasLen, len(vk.CommitmentKeys))
	c.Log("len(G1.K)", len(vk.G1.K))
	c.Log("len(CommitmentKeys)", len(vk.CommitmentKeys))
}
