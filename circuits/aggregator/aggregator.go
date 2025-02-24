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
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
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
	Proofs               [circuits.VotesPerBatch]plonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	BaseVerificationKey  plonk.BaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine] `gnark:"-"`
	VerificationKey      plonk.CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine]                    `gnark:"-"`
	DummyVerificationKey plonk.CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine]                    `gnark:"-"`
}

// checkProofs circuit method verifies each voter proof with the provided
// verification keys and public inputs. The verification keys should contain
// the dummy circuit and the main circuit verification keys in that particular
// order. The dummy circuit verification key is used to verify the proofs that
// are not from valid voters. As circuit method, it does not return any value,
// but it assert that all the proofs are valid.
func (c AggregatorCircuit) checkProofs(api frontend.API, hashes circuits.VotersHashes) {
	// initialize the verifier of the BLS12-377 curve
	verifier, err := plonk.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		circuits.FrontendError(api, "failed to create BLS12-377 verifier", err)
	}
	// decode the valid proofs indicators from the binary representation
	// take only the first len(c.Proofs) bits to avoid length mismatch
	validProofs := bits.ToBinary(api, c.ValidVotes)[:len(c.Proofs)]
	// calculate the witness for each voter and verify each proof with it
	for i := 0; i < len(c.Proofs); i++ {
		api.Println("Checking proof", i)
		api.Println("Valid proof?", validProofs[i])
		// calculate the witness for the i-th voter
		calculatedWitness, err := hashes.ToWitnessBLS12377(api, i, validProofs[i])
		if err != nil {
			circuits.FrontendError(api, "failed to calculate witness", err)
		}
		// switch the verification key to the dummy one if the proof is not valid
		vk, err := verifier.SwitchVerificationKey(c.BaseVerificationKey, validProofs[i],
			[]plonk.CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{
				c.DummyVerificationKey, c.VerificationKey, 
			})
		if err != nil {
			circuits.FrontendError(api, "failed to switch verification key", err)
		}
		// verify the proof with the calculated witness and the verification key
		if err := verifier.AssertProof(vk, c.Proofs[i], calculatedWitness); err != nil {
			circuits.FrontendError(api, "failed to verify proof", err)
		}
	}
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// calculate the voters hashes
	hashes := circuits.CalculateVotersHashes(api, c.Process, c.Votes[:])
	// check the inputs hash matches the calculated one from the voters hashes
	hashes.AssertSumIsEqual(api, c.InputsHash)
	// check all the proofs are valid and match the voters hashes as inputs
	c.checkProofs(api, hashes)
	return nil
}
