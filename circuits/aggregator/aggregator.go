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
	EncryptionPubKey [2]frontend.Variable // Part of InputsHash
	ProcessId        frontend.Variable    // Part of InputsHash
	CensusRoot       frontend.Variable    // Part of InputsHash
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

// checkInputHash circuit method checks the hash of the public-private inputs
// of the circuit with the provided InputsHash. The hash is calculated using
// the native MiMC hash function (using the same field as the circuit). As
// circuit method, it does not return any value, but it assert that the hashes
// are equal. The hash includes the census root, process id, encryption public
// key, the ballot mode params, the nullifiers, commitments, addresses and the
// encrypted ballots.
func (c AggregatorCircuit) checkInputHash(api frontend.API) {
	// group common inputs
	inputs := []frontend.Variable{c.CensusRoot, c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1]}
	inputs = append(inputs, c.BallotMode.List()...)
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
		api.Println("failed to create native mimc hash function: ", err)
		api.AssertIsEqual(0, 1)
	}
	hFn.Write(inputs...)
	// compare the hash with the provided InputsHash
	api.AssertIsEqual(c.InputsHash, hFn.Sum())
}

// checkInnerInputsHashes circuit method checks the hash of the public inputs
// of each voter proof with the provided VerifyPublicInputs. The hash is
// calculated using the MiMC hash function in the same field of the proofs. As
// circuit method, it does not return any value, but it assert that the hashes
// are equal. Each hash includes the common inputs and the voter inputs.
func (c AggregatorCircuit) checkInnerInputsHashes(api frontend.API) {
	// store the original field to reset it then and set the field to BLS12-377
	originalField := api.Compiler().Field()
	api.Compiler().Field().Set(ecc.BLS12_377.ScalarField())
	// group common inputs
	commonInputs := []frontend.Variable{c.CensusRoot, c.ProcessId, c.EncryptionPubKey[0], c.EncryptionPubKey[1]}
	commonInputs = append(commonInputs, c.BallotMode.List()...)
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
			api.Println("failed to create BLS12-377 mimc hash function: ", err)
			api.AssertIsEqual(0, 1)
		}
		// hash all the inputs
		bls12377HashFn.Write(commonInputs...)
		bls12377HashFn.Write(remainingInputs...)
		finalHash := api.Select(validHashes[i], bls12377HashFn.Sum(), frontend.Variable(1))
		// pack expected hash from each voter proof public inputs
		api.AssertIsEqual(len(c.VerifyPublicInputs[i].Public), 1)
		expectedHash, err := utils.PackScalarToVar(api, c.VerifyPublicInputs[i].Public[0])
		if err != nil {
			api.Println("failed to expected inner input hash pack scalar to variable: ", err)
			api.AssertIsEqual(0, 1)
		}
		// compare the expected hash with the calculated one
		api.AssertIsEqual(expectedHash, finalHash)
	}
	// reset the field to the original one
	api.Compiler().Field().Set(originalField)
}

// checkProofs circuit method verifies each voter proof with the provided
// verification keys and public inputs. The verification keys should contain
// the dummy circuit and the main circuit verification keys in that particular
// order. The dummy circuit verification key is used to verify the proofs that
// are not from valid voters. As circuit method, it does not return any value,
// but it assert that all the proofs are valid.
func (c AggregatorCircuit) checkProofs(api frontend.API) {
	// initialize the verifier of the BLS12-377 curve
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		api.Println("failed to create BLS12-377 verifier: ", err)
		api.AssertIsEqual(0, 1)
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	validProofs := bits.ToBinary(api, c.ValidVotes)
	for i := 0; i < len(c.VerifyProofs); i++ {
		vk, err := verifier.SwitchVerificationKey(validProofs[i], c.VerificationKeys[:])
		if err != nil {
			api.Println("failed to switch verification key: ", err)
			api.AssertIsEqual(0, 1)
		}
		if err := verifier.AssertProof(vk, c.VerifyProofs[i], c.VerifyPublicInputs[i]); err != nil {
			api.Println("failed to verify proof: ", i, err)
			api.AssertIsEqual(0, 1)
		}
	}
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// check the inputs hash
	c.checkInputHash(api)
	// // check inner circuits inputs hashes
	// c.checkInnerInputsHashes(api)
	// check all the proofs
	c.checkProofs(api)
	return nil
}
