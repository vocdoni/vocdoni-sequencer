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
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

const (
	MaxVotes  = 10
	MaxFields = 8
)

type AggregatorCircuit struct {
	InputsHash frontend.Variable `gnark:",public"`
	ValidVotes frontend.Variable `gnark:",public"`
	// The following variables are priv-public inputs, so should be hashed and
	// compared with the InputsHash. All the variables should be hashed in the
	// same order as they are defined here.

	// BallotMode is a struct that contains the common inputs for all the
	// voters. The values of this struct should be the same for all the voters
	// in the same process.
	circuits.BallotMode[frontend.Variable]
	// Other common inputs
	ProcessId  frontend.Variable // Part of InputsHash
	CensusRoot frontend.Variable // Part of InputsHash
	// Voter inputs
	Nullifiers       [MaxVotes]frontend.Variable                  // Part of InputsHash
	Commitments      [MaxVotes]frontend.Variable                  // Part of InputsHash
	Addresses        [MaxVotes]frontend.Variable                  // Part of InputsHash
	EncryptedBallots [MaxVotes][MaxFields][2][2]frontend.Variable // Part of InputsHash
	// VerifyCircuit proofs
	VerifyProofs       [MaxVotes]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	VerifyPublicInputs [MaxVotes]groth16.Witness[sw_bls12377.ScalarField]
	// VerificationKeys should contain the dummy circuit and the main circuit
	// verification keys in that particular order
	VerificationKeys [2]groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

func checkInputs(api frontend.API, mode circuits.BallotMode[frontend.Variable],
	inputsHash, processId, censusRoot frontend.Variable,
	nullifiers, commitments, addresses []frontend.Variable,
	encryptedBallots [][MaxFields][2][2]frontend.Variable,
) error {
	// group all the inputs to hash them
	inputs := []frontend.Variable{
		mode.MaxCount, mode.ForceUniqueness, mode.MaxValue, mode.MinValue, mode.MaxTotalCost,
		mode.MinTotalCost, mode.CostExp, mode.CostFromWeight, mode.EncryptionPubKey[0],
		mode.EncryptionPubKey[1], processId, censusRoot,
	}
	inputs = append(inputs, nullifiers...)
	inputs = append(inputs, commitments...)
	inputs = append(inputs, addresses...)
	// include flattened EncryptedBallots
	for _, voterBallots := range encryptedBallots {
		for _, ballot := range voterBallots {
			inputs = append(inputs, ballot[0][0], ballot[0][1], ballot[1][0], ballot[1][1])
		}
	}
	// hash the inputs
	hFn, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("error creating hash function: %w", err)
	}
	hFn.Write(inputs...)
	// compare the hash with the provided InputsHash
	api.AssertIsEqual(inputsHash, hFn.Sum())
	return nil
}

func (c *AggregatorCircuit) Define(api frontend.API) error {
	// check the inputs of the circuit
	if err := checkInputs(api,
		c.BallotMode, c.InputsHash, c.ProcessId, c.CensusRoot,
		c.Nullifiers[:], c.Commitments[:], c.Addresses[:], c.EncryptedBallots[:],
	); err != nil {
		return fmt.Errorf("inputs check error: %w", err)
	}
	// initialize the verifier
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("failed to create BLS12-377 verifier: %w", err)
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	validProofs := bits.ToBinary(api, c.ValidVotes)
	expectedValidVotes, totalValidVotes := frontend.Variable(0), frontend.Variable(0)
	for i := 0; i < len(c.VerifyProofs); i++ {
		vk, err := verifier.SwitchVerificationKey(validProofs[i], c.VerificationKeys[:])
		if err != nil {
			return fmt.Errorf("failed to switch verification key: %w", err)
		}
		if err := verifier.AssertProof(vk, c.VerifyProofs[i], c.VerifyPublicInputs[i]); err != nil {
			return fmt.Errorf("failed to verify proof %d: %w", i, err)
		}
		expectedValidVotes = api.Add(expectedValidVotes, validProofs[i])
		totalValidVotes = api.Add(totalValidVotes, validProofs[i])
	}
	api.AssertIsEqual(expectedValidVotes, totalValidVotes)
	return nil
}
