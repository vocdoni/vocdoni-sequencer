// aggregator package contains the Gnark circuit defiinition that aggregates
// some votes and proves the validity of the aggregation. The circuit checks
// every single verification proof generating a single proof for the whole
// aggregation. Every voter proof should use the same values for the following
// inputs:
//   - MaxCount
//   - ForceUniqueness
//   - MaxValue
//   - MinValue
//   - MaxTotalCost
//   - MinTotalCost
//   - CostExp
//   - CostFromWeight
//   - EncryptionPubKey
//   - ProcessId
//   - CensusRoot
//
// All these values are common for the same process.
//
// The circuit also checks the other inputs that are unique for each voter:
//   - Nullifier
//   - Commitment
//   - Address
//   - Ballot
//   - VerifyProof (generated with the VerifyVoteCircuit)
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
	Witnesses       [circuits.VotesPerBatch]groth16.Witness[sw_bls12377.ScalarField]
	VerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

func (c AggregatorCircuit) Define(api frontend.API) error {
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
	return nil
}
