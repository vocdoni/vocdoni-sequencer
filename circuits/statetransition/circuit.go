package statetransition

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
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
	ProcessID     state.MerkleProof
	CensusRoot    state.MerkleProof
	BallotMode    state.MerkleProof
	EncryptionKey state.MerkleProof
	ResultsAdd    state.MerkleTransition
	ResultsSub    state.MerkleTransition
	Ballot        [VoteBatchSize]state.MerkleTransition
	Commitment    [VoteBatchSize]state.MerkleTransition

	AggregatedProof circuits.InnerProofBW6761
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	if err := circuit.VerifyAggregatedWitnessHash(api, HashFn); err != nil {
		return err
	}
	if err := circuit.VerifyAggregatedProof(api); err != nil {
		return err
	}
	circuit.VerifyMerkleProofs(api, HashFn)
	circuit.VerifyMerkleTransitions(api, HashFn)
	circuit.VerifyBallots(api)
	return nil
}

func (circuit Circuit) AggregatedWitnessInputs() []frontend.Variable {
	// all of the following values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// ProcessID
	// CensusRoot
	// BallotMode
	// EncryptionKey
	// Nullifiers
	// Ballots
	// Addressess
	// Commitments

	inputs := []frontend.Variable{
		circuit.ProcessID.Value,
		circuit.CensusRoot.Value,
		circuit.BallotMode.Value,
		circuit.EncryptionKey.Value,
	}
	for _, mt := range circuit.Ballot {
		inputs = append(inputs, mt.NewKey) // Nullifier
	}
	for _, mt := range circuit.Ballot {
		inputs = append(inputs, mt.NewCiphertexts.Serialize()...) // Ballot
	}
	for _, mt := range circuit.Commitment {
		inputs = append(inputs, mt.NewKey) // Address
	}
	for _, mt := range circuit.Commitment {
		inputs = append(inputs, mt.NewValue) // Commitment
	}
	return inputs
}

func (circuit Circuit) VerifyAggregatedWitnessHash(api frontend.API, hFn utils.Hasher) error {
	api.AssertIsEqual(len(circuit.AggregatedProof.Witness.Public), 1)
	publicInput, err := utils.PackScalarToVar(api, &circuit.AggregatedProof.Witness.Public[0])
	if err != nil {
		return fmt.Errorf("failed to pack scalar to var: %w", err)
	}
	hash, err := hFn(api, circuit.AggregatedWitnessInputs()...)
	if err != nil {
		return fmt.Errorf("failed to hash: %w", err)
	}
	api.AssertIsEqual(hash, publicInput)
	return nil
}

func (circuit Circuit) VerifyAggregatedProof(api frontend.API) error {
	// initialize the verifier
	verifier, err := groth16.NewVerifier[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](api)
	if err != nil {
		return fmt.Errorf("failed to create bw6761 verifier: %w", err)
	}
	// verify the proof with the hash as input and the fixed verification key
	if err := verifier.AssertProof(circuit.AggregatedProof.VK, circuit.AggregatedProof.Proof, circuit.AggregatedProof.Witness); err != nil {
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

func CircuitPlaceholder() *Circuit {
	proof, err := DummyInnerProof(0)
	if err != nil {
		panic(err)
	}
	return CircuitPlaceholderWithProof(proof)
}

func CircuitPlaceholderWithProof(proof *circuits.InnerProofBW6761) *Circuit {
	return &Circuit{
		AggregatedProof: *proof,
	}
}

func DummyInnerProof(inputsHash frontend.Variable) (*circuits.InnerProofBW6761, error) {
	_, witness, proof, vk, err := dummy.Prove(
		dummy.PlaceholderWithConstraints(0), dummy.Assignment(inputsHash),
		ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, err
	}
	// parse dummy proof and witness
	dummyProof, err := groth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof)
	if err != nil {
		return nil, fmt.Errorf("dummy proof value error: %w", err)
	}
	dummyWitness, err := groth16.ValueOfWitness[sw_bw6761.ScalarField](witness)
	if err != nil {
		return nil, fmt.Errorf("dummy witness value error: %w", err)
	}
	// set fixed dummy vk in the placeholders
	dummyVK, err := groth16.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](vk)
	if err != nil {
		return nil, fmt.Errorf("dummy vk value error: %w", err)
	}

	return &circuits.InnerProofBW6761{
		Proof:   dummyProof,
		Witness: dummyWitness,
		VK:      dummyVK,
	}, nil
}
