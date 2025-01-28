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
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
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
	circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]
	// Other common inputs
	EncryptionPubKey [2]emulated.Element[sw_bn254.ScalarField] // Part of InputsHash
	ProcessId        emulated.Element[sw_bn254.ScalarField]    // Part of InputsHash
	CensusRoot       emulated.Element[sw_bn254.ScalarField]    // Part of InputsHash
	// Voter inputs
	Nullifiers       [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	Commitments      [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	Addresses        [MaxVotes]emulated.Element[sw_bn254.ScalarField]                  // Part of InputsHash
	EncryptedBallots [MaxVotes][MaxFields][2][2]emulated.Element[sw_bn254.ScalarField] // Part of InputsHash
	// Inner proofs (from VerifyVoteCircuit) and verification keys (base is the
	// real vk and dummy is used for no valid proofs in the scenario where there
	// are less valid votes than MaxVotes)
	Proofs               [MaxVotes]circuits.InnerProofBLS12377
	BaseVerificationKey  groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
	DummyVerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
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
	hashInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.ProcessId, c.CensusRoot, c.EncryptionPubKey[0], c.EncryptionPubKey[1]}
	hashInputs = append(hashInputs, c.BallotMode.List()...)
	hashInputs = append(hashInputs, c.Nullifiers[:]...)
	hashInputs = append(hashInputs, c.Commitments[:]...)
	hashInputs = append(hashInputs, c.Addresses[:]...)
	// include flattened EncryptedBallots
	for _, voterBallots := range c.EncryptedBallots {
		for _, ballot := range voterBallots {
			hashInputs = append(hashInputs, ballot[0][0], ballot[0][1], ballot[1][0], ballot[1][1])
		}
	}
	// hash the inputs
	h, err := mimc7.NewMiMC(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create emulated MiMC hash function", err)
	}
	h.Write(hashInputs...)
	finalHash, err := utils.PackScalarToVar(api, h.Sum())
	if err != nil {
		circuits.FrontendError(api, "failed to pack scalar to variable", err)
	}
	// compare the hash with the provided InputsHash
	api.AssertIsEqual(c.InputsHash, finalHash)
}

// checkInnerInputsHashes circuit method checks the hash of the public inputs
// of each voter proof with the provided VerifyPublicInputs. The hash is
// calculated using the MiMC hash function in the same field of the proofs. As
// circuit method, it does not return any value, but it assert that the hashes
// are equal. Each hash includes the common inputs and the voter inputs.
func (c AggregatorCircuit) checkInnerInputsHashes(api frontend.API) {
	hashFn, err := mimc7.NewMiMC(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create emulated MiMC hash function", err)
	}
	// group common inputs
	commonInputs := []emulated.Element[sw_bn254.ScalarField]{
		c.ProcessId, c.CensusRoot, c.EncryptionPubKey[0], c.EncryptionPubKey[1]}
	commonInputs = append(commonInputs, c.BallotMode.List()...)
	// iterate over each voter inputs to group the remaining ones and calculate
	// every voter hash
	validHashes := api.ToBinary(c.ValidVotes)
	for i := 0; i < MaxVotes; i++ {
		// ensure the proof is valid (it has a single public input, the
		// expected hash)
		api.AssertIsEqual(len(c.Proofs[i].Witness.Public), 1)
		// group remaining inputs
		remainingInputs := []emulated.Element[sw_bn254.ScalarField]{c.Addresses[i], c.Nullifiers[i], c.Commitments[i]}
		for j := 0; j < MaxFields; j++ {
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][0][1])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][0])
			remainingInputs = append(remainingInputs, c.EncryptedBallots[i][j][1][1])
		}
		// calculate the hash
		hashFn.Write(commonInputs...)
		hashFn.Write(remainingInputs...)
		resultHash := hashFn.Sum()
		calculatedHash, err := utils.PackScalarToVar(api, resultHash)
		if err != nil {
			circuits.FrontendError(api, "failed to pack scalar to variable", err)
		}
		// if the proof is a dummy one, the hash should be one (same value of
		// the public input of the dummy circuit)
		finalHash := api.Select(validHashes[i], calculatedHash, frontend.Variable(1))
		// pack expected hash from each voter proof public inputs
		expectedHash, err := utils.PackScalarToVar(api, c.Proofs[i].Witness.Public[0])
		if err != nil {
			circuits.FrontendError(api, "failed to pack scalar to variable", err)
		}
		// compare the expected hash with the calculated one
		api.AssertIsEqual(expectedHash, finalHash)
		// reset the hash function
		hashFn.Reset()
	}
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
		circuits.FrontendError(api, "failed to create BLS12-377 verifier", err)
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	validProofs := bits.ToBinary(api, c.ValidVotes)
	for i := 0; i < len(c.Proofs); i++ {
		api.Println("proof", i)
		for j, limb := range c.Proofs[i].Witness.Public[0].Limbs {
			api.Println("hash limb", j, limb)
		}
		vk, err := verifier.SwitchVerificationKey(validProofs[i], []groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			c.DummyVerificationKey,
			c.BaseVerificationKey,
		})
		if err != nil {
			circuits.FrontendError(api, "failed to switch verification key", err)
		}
		if err := verifier.AssertProof(vk, c.Proofs[i].Proof, c.Proofs[i].Witness); err != nil {
			circuits.FrontendError(api, "failed to verify proof", err)
		}
	}
}

func (c AggregatorCircuit) Define(api frontend.API) error {
	// check the inputs hash
	c.checkInputHash(api)
	// check inner circuits inputs hashes
	// c.checkInnerInputsHashes(api)
	// check all the proofs
	c.checkProofs(api)
	return nil
}
