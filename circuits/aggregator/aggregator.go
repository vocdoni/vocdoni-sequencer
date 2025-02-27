// aggregator package contains the Gnark circuit defiinition that aggregates
// some votes and proves the validity of the aggregation. The circuit checks
// every single verification proof generating a single proof for the whole
// aggregation. It also checks that the number of valid votes and that the
// hash of the witnesses is the expected.
package aggregator

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type AggregatorCircuit struct {
	ValidProofs     frontend.Variable                      `gnark:",public"`
	WitnessesHash   emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Proofs          [circuits.VotesPerBatch]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	Witnesses       [circuits.VotesPerBatch]groth16.Witness[sw_bls12377.ScalarField]
	VerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

// checkWitnessesHash checks that the hash of the witnesses is the expected
// value. The hash of the witnesses is calculated using the MiMC7 hash function
// over emulated.Element[sw_bn254.ScalarField] inputs. The expected number of
// inputs is the number of votes times 2, where each vote has two public inputs
// (valid vote indicator and inputs hash).
func (c AggregatorCircuit) checkWitnessesHash(api frontend.API) {
	// initialize the hash function
	hFn, err := mimc7.NewMiMC(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create MiMC hash function", err)
		return
	}
	// To build the hash of the witnesses, we expect to have two public inputs
	// per proof:
	//  - the first one should be an emulated frontend.Variable wich indicates
	//    if the proof is valid or not.
	//    (Original: 1 or 0, Emulated: [1 0 0 0] or [0 0 0 0])
	//  - the second one should be the hash of the inputs of the vote verifier
	//    circuit as emulated emulated.Element[sw_bn254.ScalarField]. As
	//    emulated emulated.Element, each original limb of the hash should be
	//    represented as a slice of 4 elements, the first limb contains the
	//    original value and the rest are zeros.
	//    (Original: [1 2 3 4], Emulated: [[1 0 0 0] [2 0 0 0] [3 0 0 0] [4 0 0 0])
	// The hash function expect emulated.Element[sw_bn254.ScalarField] as inputs
	// so we need to convert the public inputs to the expected type, keeping the
	// the first public input as is and reconstructing the second one grouping
	// each first limb in a slice of 4 elements.
	for _, w := range c.Witnesses {
		// check that the number of public inputs is the expected
		api.AssertIsEqual(len(w.Public), 5)
		// include the valid vote indicator in the hash
		hFn.Write(emulated.Element[sw_bn254.ScalarField]{Limbs: w.Public[0].Limbs})
		// reconstruct the hash of the inputs of the vote verifier circuit
		inputsHashLimbs := emulated.Element[sw_bn254.ScalarField]{Limbs: []frontend.Variable{}}
		for _, pub := range w.Public[1:] {
			inputsHashLimbs.Limbs = append(inputsHashLimbs.Limbs, pub.Limbs[0])
		}
		// include the inputs hash in the hash
		hFn.Write(inputsHashLimbs)
	}
	// check that the hash of the witnesses is the expected
	hFn.AssertSumIsEqual(c.WitnessesHash)
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
	// check the hash of the witnesses
	c.checkWitnessesHash(api)
	// check the proofs
	c.checkProofs(api)
	return nil
}
