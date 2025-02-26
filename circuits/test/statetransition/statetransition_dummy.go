package statetransitiontest

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
)

// DummyAggCircuit is dummy aggregator circuit
type DummyAggCircuit struct {
	InputsHash    emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	ValidVotes    frontend.Variable                      `gnark:",public"`
	SecretInput   frontend.Variable                      `gnark:",secret"`
	nbConstraints int
}

// Define defines a dummy aggregator circuit
func (c *DummyAggCircuit) Define(api frontend.API) error {
	cmtr, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api is not a commiter")
	}
	secret, err := cmtr.Commit(c.SecretInput)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(secret, 0)

	res := api.Mul(c.SecretInput, c.SecretInput)
	for i := 2; i < c.nbConstraints; i++ {
		res = api.Mul(res, c.SecretInput)
	}
	api.AssertIsEqual(c.ValidVotes, c.ValidVotes)
	for _, limb := range c.InputsHash.Limbs {
		api.AssertIsEqual(limb, limb)
	}
	return nil
}

// DummyAggPlaceholder function returns the placeholder of a dummy aggregator circuit for
// the constraint.ConstraintSystem provided.
func DummyAggPlaceholder(mainDummyAggCircuit constraint.ConstraintSystem) *DummyAggCircuit {
	return &DummyAggCircuit{nbConstraints: mainDummyAggCircuit.GetNbConstraints()}
}

// DummyAggPlaceholderWithConstraints returns the placeholder of a dummy aggregator circuit
// with the desired number of constraints.
func DummyAggPlaceholderWithConstraints(nbConstraints int) *DummyAggCircuit {
	return &DummyAggCircuit{nbConstraints: nbConstraints}
}

// DummyAggAssignment returns the assignment of a dummy aggregator circuit.
func DummyAggAssignment(inputHash, validVotes frontend.Variable) *DummyAggCircuit {
	return &DummyAggCircuit{
		InputsHash:  emulated.ValueOf[sw_bn254.ScalarField](inputHash),
		ValidVotes:  validVotes,
		SecretInput: 1,
	}
}

// DummyAggProofPlaceholder returns a placeholder for a dummy aggregator proof
func DummyAggProofPlaceholder() (
	*groth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine],
	*groth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl],
) {
	ccs, _, vk, err := dummy.CompileAndSetup(DummyAggPlaceholderWithConstraints(0), circuits.AggregatorCurve.ScalarField())
	if err != nil {
		panic(err)
	}
	// parse dummy proof and witness
	dummyProof := groth16.PlaceholderProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](ccs)
	// set fixed dummy vk in the placeholders
	dummyVK, err := groth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](vk)
	if err != nil {
		panic(err)
	}
	return &dummyProof, &dummyVK
}

// DummyAggProof returns a dummy aggregator proof
func DummyAggProof(inputsHash, validVotes frontend.Variable) (
	*groth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine],
	*groth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl], error,
) {
	_, _, proof, vk, err := dummy.Prove(
		DummyAggPlaceholderWithConstraints(0), DummyAggAssignment(inputsHash, validVotes),
		circuits.StateTransitionCurve.ScalarField(), circuits.AggregatorCurve.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	// parse dummy proof and witness
	dummyProof, err := groth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof)
	if err != nil {
		return nil, nil, fmt.Errorf("dummy proof value error: %w", err)
	}
	// set fixed dummy vk in the placeholders
	dummyVK, err := groth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](vk)
	if err != nil {
		return nil, nil, fmt.Errorf("dummy vk value error: %w", err)
	}
	return &dummyProof, &dummyVK, nil
}
