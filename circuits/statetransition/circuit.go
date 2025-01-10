package statetransition

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

var HashFn = utils.MiMCHasher

const (
	// votes that were processed in AggregatedProof
	VoteBatchSize = 10
)

type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumNewVotes    frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	AggregatedProof        groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine] // TODO: check curve
	AggregatedProofWitness groth16.Witness[sw_bls12377.ScalarField]
	AggregatedProofVK      groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`

	ProcessID     state.MerkleProof
	CensusRoot    state.MerkleProof
	BallotMode    state.MerkleProof
	EncryptionKey state.MerkleProof
	ResultsAdd    state.MerkleTransition
	ResultsSub    state.MerkleTransition
	Ballot        [VoteBatchSize]state.MerkleTransition
	Commitment    [VoteBatchSize]state.MerkleTransition
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	if err := circuit.VerifyAggregatedZKProof(api, HashFn); err != nil {
		return err
	}
	circuit.VerifyMerkleProofs(api, HashFn)
	circuit.VerifyMerkleTransitions(api, HashFn)
	circuit.VerifyBallots(api)
	return nil
}

func (circuit Circuit) VerifyAggregatedZKProof(api frontend.API, hFn utils.Hasher) error {
	// all of the following values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// they are extracted from the MerkleProofs:
	// ProcessID     := circuit.ProcessID.Value
	// CensusRoot    := circuit.CensusRoot.Value
	// BallotMode    := circuit.BallotMode.Value
	// EncryptionKey := circuit.EncryptionKey.Value
	// Nullifiers    := circuit.Ballot[i].NewKey
	// Ballots       := circuit.Ballot[i].NewValue
	// Addressess    := circuit.Commitment[i].NewKey
	// Commitments   := circuit.Commitment[i].NewValue

	inputs := []frontend.Variable{
		circuit.ProcessID.Value,
		circuit.CensusRoot.Value,
		circuit.BallotMode.Value,
		circuit.EncryptionKey.Value,
	}
	for _, mt := range circuit.Ballot {
		inputs = append(inputs, mt.NewKey, mt.NewValue) // Nullifier, Ballot
	}
	for _, mt := range circuit.Commitment {
		inputs = append(inputs, mt.NewKey, mt.NewValue) // Address, Commitment
	}
	// hash the inputs
	hash, err := hFn(api, inputs...)
	if err != nil {
		return err
	}

	publicInput, err := utils.PackScalarToVar(api, &circuit.AggregatedProofWitness.Public[0])
	if err != nil {
		return fmt.Errorf("failed to pack scalar to var: %w", err)
	}
	api.AssertIsEqual(hash, publicInput)

	// initialize the verifier
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("failed to create BLS12-377 verifier: %w", err)
	}
	// verify the proof with the hash as input and the fixed verification key
	if err := verifier.AssertProof(circuit.AggregatedProofVK, circuit.AggregatedProof, circuit.AggregatedProofWitness); err != nil {
		return fmt.Errorf("failed to verify aggregated proof: %w", err)
	}

	return nil
}

func (circuit Circuit) VerifyMerkleProofs(api frontend.API, hFn utils.Hasher) {
	api.Println("verify ProcessID, CensusRoot, BallotMode and EncryptionKey belong to RootHashBefore")
	circuit.ProcessID.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.CensusRoot.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.BallotMode.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.EncryptionKey.VerifyProof(api, hFn, circuit.RootHashBefore)
}

func (circuit Circuit) VerifyMerkleTransitions(api frontend.API, hFn utils.Hasher) {
	// verify chain of tree transitions, order here is fundamental.
	api.Println("tree transition starts with RootHashBefore:", util.PrettyHex(circuit.RootHashBefore))
	root := circuit.RootHashBefore
	for i := range circuit.Ballot {
		root = circuit.Ballot[i].Verify(api, hFn, root)
	}
	for i := range circuit.Commitment {
		root = circuit.Commitment[i].Verify(api, hFn, root)
	}
	root = circuit.ResultsAdd.Verify(api, hFn, root)
	root = circuit.ResultsSub.Verify(api, hFn, root)
	api.Println("and final root is", util.PrettyHex(root), "should be equal to RootHashAfter", util.PrettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
}

// VerifyBallots counts the ballots using homomorphic encrpytion
func (circuit Circuit) VerifyBallots(api frontend.API) {
	ballotSum, overwrittenSum, zero := elgamal.NewCiphertexts(), elgamal.NewCiphertexts(), elgamal.NewCiphertexts()
	var ballotCount, overwrittenCount frontend.Variable = 0, 0

	for _, b := range circuit.Ballot {
		// TODO: check that Hash(NewCiphertext) matches b.NewValue
		// and Hash(OldCiphertext) matches b.OldValue
		ballotSum.Add(api, ballotSum,
			elgamal.NewCiphertexts().Select(api, b.IsInsertOrUpdate(api), &b.NewCiphertexts, zero))

		overwrittenSum.Add(api, overwrittenSum,
			elgamal.NewCiphertexts().Select(api, b.IsUpdate(api), &b.OldCiphertexts, zero))

		ballotCount = api.Add(ballotCount, api.Select(b.IsInsertOrUpdate(api), 1, 0))
		overwrittenCount = api.Add(overwrittenCount, api.Select(b.IsUpdate(api), 1, 0))
	}

	circuit.ResultsAdd.NewCiphertexts.AssertIsEqual(api,
		circuit.ResultsAdd.OldCiphertexts.Add(api, &circuit.ResultsAdd.OldCiphertexts, ballotSum))
	circuit.ResultsSub.NewCiphertexts.AssertIsEqual(api,
		circuit.ResultsSub.OldCiphertexts.Add(api, &circuit.ResultsSub.OldCiphertexts, overwrittenSum))
	api.AssertIsEqual(circuit.NumNewVotes, ballotCount)
	api.AssertIsEqual(circuit.NumOverwrites, overwrittenCount)
}
