// aggregator package contains the Gnark circuit defiinition that aggregates
// some votes and proves the validity of the aggregation. The circuit checks
// every single verification proof generating a single proof for the whole
// aggregation. It also checks that the number of valid votes and that the
// hash of the witnesses is the expected.
package aggregator

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type AggregatorCircuit struct {
	ValidProofs     frontend.Variable `gnark:",public"`
	Proofs          [circuits.VotesPerBatch]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	Witnesses       [circuits.VotesPerBatch]groth16.Witness[sw_bls12377.ScalarField]                 `gnark:",public"`
	VerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

// checkProofs checks that the proofs are valid and that the number of valid
// proofs is the expected. The verification of the proofs is done using the
// provided verification key and the public inputs of the witnesses. The number
// of valid proofs is calculated by counting the number of valid votes. A vote
// is considered valid if the first limb of the first public input in the
// witness is 1, otherwise it is considered invalid. The number of valid votes
// is calculated by adding the result of the AND operation between the last
// valid vote and the current vote. The number of valid votes is the expected
// number of valid proofs. Only the first n proofs can be valid, so the
// counting stops after the first invalid proof.
func (c AggregatorCircuit) checkProofs(api frontend.API) {
	// initialize the verifier of the BLS12-377 curve
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		circuits.FrontendError(api, "failed to create BLS12-377 verifier", err)
	}
	// initialize the variables to count the number of valid votes
	validVotes := frontend.Variable(0)
	// only the first n proofs can be valid, so we need to store if the previous
	// proof was valid to stop counting after the first invalid one
	lastValidVote := frontend.Variable(1)
	// verify each proof with the provided public inputs and the fixed
	// verification key
	for i := range len(c.Proofs) {
		// if the proof is valid, the first limb of the first input in the
		// witness should be 1, otherwise it should be 0
		// but only accepts the n first valid proofs so, to update the
		// number of valid votes correctly, we add the result of the AND
		// operation between the last valid vote and the current vote
		isValid := api.And(lastValidVote, c.Witnesses[i].Public[0].Limbs[0])
		lastValidVote = isValid
		// count the number of valid votes
		validVotes = api.Add(validVotes, isValid)
		// verify the proof
		if err := verifier.AssertProof(c.VerificationKey, c.Proofs[i], c.Witnesses[i], groth16.WithCompleteArithmetic()); err != nil {
			circuits.FrontendError(api, "failed to verify proof", err)
		}
	}
	// check that the number of valid votes is the expected
	api.AssertIsEqual(c.ValidProofs, validVotes)
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// check the proofs
	c.checkProofs(api)
	return nil
}
