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
//   - EncryptedBallots
//   - VerifyProof (generated with the VerifyVoteCircuit)
package aggregator

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

type AggregatorCircuit struct {
	// InputsHash frontend.Variable `gnark:",public"`
	InputsHash emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	ValidVotes frontend.Variable                      `gnark:",public"`
	// The following variables are priv-public inputs, so should be hashed and
	// compared with the InputsHash. All the variables should be hashed in the
	// same order as they are defined here.
	Process circuits.Process[emulated.Element[sw_bn254.ScalarField]]
	Votes   [circuits.VotesPerBatch]circuits.EmulatedVote[sw_bn254.ScalarField]
	// Inner proofs (from VerifyVoteCircuit) and verification keys (base is the
	// real vk and dummy is used for no valid proofs in the scenario where there
	// are less valid votes than MaxVotes)
	Proofs               [circuits.VotesPerBatch]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	BaseVerificationKey  groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
	DummyVerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

// calculateVotersHashes circuit method calculates the hash of each voter using
// the common inputs and the unique inputs of each voter. It returns a
// VotersHashes struct that contains the hashes of the voters and allows to
// generate the witness for the i-th voter or to assert that the sum of the
// hashes is equal to the expected value.
func (c AggregatorCircuit) calculateVotersHashes(api frontend.API) VotersHashes {
	// initialize the hashes of the voters
	votersHashes := [circuits.VotesPerBatch]emulated.Element[sw_bn254.ScalarField]{}
	// group common inputs
	commonInputs := c.Process.Serialize()
	// iterate over the voters
	for i := 0; i < circuits.VotesPerBatch; i++ {
		// group remaining inputs, those that are unique for each voter
		voterInputs := append(commonInputs, c.Votes[i].Address, c.Votes[i].Nullifier, c.Votes[i].Commitment)
		voterInputs = append(voterInputs, c.Votes[i].Ballot.Serialize()...)
		// calculate the voter hash and store it
		votersHashes[i] = VoterHashFn(api, voterInputs...)
	}
	return VotersHashes{votersHashes}
}

// checkProofs circuit method verifies each voter proof with the provided
// verification keys and public inputs. The verification keys should contain
// the dummy circuit and the main circuit verification keys in that particular
// order. The dummy circuit verification key is used to verify the proofs that
// are not from valid voters. As circuit method, it does not return any value,
// but it assert that all the proofs are valid.
func (c AggregatorCircuit) checkProofs(api frontend.API, hashes VotersHashes) {
	// initialize the verifier of the BLS12-377 curve
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		circuits.FrontendError(api, "failed to create BLS12-377 verifier", err)
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	validProofs := bits.ToBinary(api, c.ValidVotes)
	for i := 0; i < len(c.Proofs); i++ {
		// switch the verification key between the base and the dummy one if
		// the proof is valid or not
		vk, err := verifier.SwitchVerificationKey(validProofs[i],
			[]groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
				c.DummyVerificationKey,
				c.BaseVerificationKey,
			},
		)
		if err != nil {
			circuits.FrontendError(api, "failed to switch verification key", err)
		}
		// calculate the witness for the i-th voter
		calculatedWitness, err := hashes.ToWitness(api, i, validProofs[i])
		if err != nil {
			circuits.FrontendError(api, "failed to calculate witness", err)
		}
		// verify the proof
		if err := verifier.AssertProof(vk, c.Proofs[i], calculatedWitness); err != nil {
			circuits.FrontendError(api, "failed to verify proof", err)
		}
	}
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// calculate the voters hashes
	hashes := c.calculateVotersHashes(api)
	// check the inputs hash matches the calculated one from the voters hashes
	hashes.AssertSumIsEqual(api, c.InputsHash)
	// check all the proofs are valid and match the voters hashes as inputs
	c.checkProofs(api, hashes)
	return nil
}
