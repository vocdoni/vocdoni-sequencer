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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
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

func (c AggregatorCircuit) checkInputHash(api frontend.API) {
	// group common inputs
	inputs := []frontend.Variable{
		c.CensusRoot, c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1],
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue,
		c.MaxTotalCost, c.MinTotalCost, c.CostExp, c.CostFromWeight}
	inputs = append(inputs, c.Nullifiers[:]...)
	inputs = append(inputs, c.Commitments[:]...)
	inputs = append(inputs, c.Addresses[:]...)
	// include flattened EncryptedBallots
	for _, voterBallots := range c.EncryptedBallots {
		for _, ballot := range voterBallots {
			inputs = append(inputs, ballot[0][0], ballot[0][1], ballot[1][0], ballot[1][1])
		}
	}
	// hash the inputs
	hFn, err := mimc.NewMiMC(api)
	if err != nil {
		api.Println("failed to create native mimc hash function: %w", err)
		api.AssertIsEqual(0, 1)
	}
	hFn.Write(inputs...)
	// compare the hash with the provided InputsHash
	api.AssertIsEqual(c.InputsHash, hFn.Sum())
}

func (c AggregatorCircuit) checkInnerInputsHashes(api frontend.API) {
	// store the original field to reset it then and set the field to BLS12-377
	originalField := api.Compiler().Field()
	api.Compiler().Field().Set(ecc.BLS12_377.ScalarField())
	// group common inputs
	commonInputs := []frontend.Variable{
		c.CensusRoot, c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1],
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue,
		c.MaxTotalCost, c.MinTotalCost, c.CostExp, c.CostFromWeight}
	// iterate over each voter inputs to group the remaining ones and calculate
	// every voter hash
	validHashes := api.ToBinary(c.ValidVotes)
	for i := 0; i < MaxVotes; i++ {
		remainingInputs := []frontend.Variable{c.Addresses[i], c.Nullifiers[i], c.Commitments[i]}
		for j := 0; j < MaxFields; j++ {
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][1])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][1])
		}
		// instance bls12377 hash function
		bls12377HashFn, err := mimc.NewMiMC(api)
		if err != nil {
			api.Println("failed to create BLS12-377 mimc hash function: %w", err)
			api.AssertIsEqual(0, 1)
		}
		// hash all the inputs
		bls12377HashFn.Write(commonInputs...)
		bls12377HashFn.Write(remainingInputs...)
		finalHash := api.Mul(bls12377HashFn.Sum(), validHashes[i])
		// pack expected hash from each voter proof public inputs
		api.AssertIsEqual(len(c.VerifyPublicInputs[i].Public), 1)
		expectedHash, err := utils.PackScalarToVar(api, c.VerifyPublicInputs[i].Public[0])
		if err != nil {
			api.Println("failed to expected inner input hash pack scalar to variable: %w", err)
			api.AssertIsEqual(0, 1)
		}
		// compare the expected hash with the calculated one
		api.AssertIsEqual(expectedHash, finalHash)
	}
	// reset the field to the original one
	api.Compiler().Field().Set(originalField)
}

func (c AggregatorCircuit) checkProofs(api frontend.API) {
	// initialize the verifier of the BLS12-377 curve
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		api.Println("failed to create BLS12-377 verifier: %w", err)
		api.AssertIsEqual(0, 1)
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	validProofs := bits.ToBinary(api, c.ValidVotes)
	for i := 0; i < len(c.VerifyProofs); i++ {
		vk, err := verifier.SwitchVerificationKey(validProofs[i], c.VerificationKeys[:])
		if err != nil {
			api.Println("failed to switch verification key: %w", err)
			api.AssertIsEqual(0, 1)
		}
		if err := verifier.AssertProof(vk, c.VerifyProofs[i], c.VerifyPublicInputs[i]); err != nil {
			api.Println("failed to verify proof %d: %w", i, err)
			api.AssertIsEqual(0, 1)
		}
	}
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// check the inputs hash
	c.checkInputHash(api)
	// check inner circuits inputs hashes
	c.checkInnerInputsHashes(api)
	// check all the proofs
	c.checkProofs(api)
	return nil
}
