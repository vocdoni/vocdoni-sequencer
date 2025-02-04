package statetransition

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

var HashFn = utils.MiMCHasher

type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumNewVotes    frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS
	Process circuits.Process[frontend.Variable]
	Votes   [circuits.VotesPerBatch]Vote
	Results Results

	ProcessProofs ProcessProofs
	VotesProofs   VotesProofs
	ResultsProofs ResultsProofs

	AggregatedProof circuits.InnerProofBW6761
}

type Results struct {
	OldResultsAdd circuits.Ballot
	OldResultsSub circuits.Ballot
	NewResultsAdd circuits.Ballot
	NewResultsSub circuits.Ballot
}

type ProcessProofs struct {
	ID            MerkleProof
	CensusRoot    MerkleProof
	BallotMode    MerkleProof
	EncryptionKey MerkleProof
}

type VotesProofs struct {
	Ballot     [circuits.VotesPerBatch]MerkleTransition // Key is Nullifier, LeafHash is smt.Hash1(Ballot.Serialize())
	Commitment [circuits.VotesPerBatch]MerkleTransition // Key is Address, LeafHash is smt.Hash1(Commitment)
}

type ResultsProofs struct {
	ResultsAdd MerkleTransition
	ResultsSub MerkleTransition
}

type Vote struct {
	circuits.Vote[frontend.Variable]
	OverwrittenBallot circuits.Ballot
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	circuit.VerifyAggregatedWitnessHash(api)
	circuit.VerifyAggregatedProof(api)
	circuit.VerifyMerkleProofs(api, HashFn)
	circuit.VerifyMerkleTransitions(api, HashFn)
	circuit.VerifyLeafHashes(api, HashFn)
	circuit.VerifyBallots(api)
	return nil
}

func (circuit Circuit) VerifyAggregatedWitnessHash(api frontend.API) {
	api.AssertIsEqual(len(circuit.AggregatedProof.Witness.Public), 1)
	publicInput, err := utils.PackScalarToVar(api, circuit.AggregatedProof.Witness.Public[0])
	if err != nil {
		circuits.FrontendError(api, "failed to pack scalar to var: ", err)
	}
	hash, err := HashFn(api, circuits.AggregatedWitnessInputsAsVars(api, circuit.Process, circuit.ListVotes())...)
	if err != nil {
		circuits.FrontendError(api, "failed to hash: ", err)
	}
	api.AssertIsEqual(hash, publicInput)
}

func (circuit Circuit) VerifyAggregatedProof(api frontend.API) {
	// initialize the verifier
	verifier, err := groth16.NewVerifier[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](api)
	if err != nil {
		circuits.FrontendError(api, "failed to create bw6761 verifier: ", err)
	}
	// verify the proof with the hash as input and the fixed verification key
	if err := verifier.AssertProof(circuit.AggregatedProof.VK, circuit.AggregatedProof.Proof, circuit.AggregatedProof.Witness); err != nil {
		circuits.FrontendError(api, "failed to verify aggregated proof: ", err)
	}
}

func (circuit Circuit) VerifyMerkleProofs(api frontend.API, hFn utils.Hasher) {
	api.Println("verify ProcessID, CensusRoot, BallotMode and EncryptionKey belong to RootHashBefore")
	circuit.ProcessProofs.ID.Verify(api, hFn, circuit.RootHashBefore)
	circuit.ProcessProofs.CensusRoot.Verify(api, hFn, circuit.RootHashBefore)
	circuit.ProcessProofs.BallotMode.Verify(api, hFn, circuit.RootHashBefore)
	circuit.ProcessProofs.EncryptionKey.Verify(api, hFn, circuit.RootHashBefore)
}

func (circuit Circuit) VerifyMerkleTransitions(api frontend.API, hFn utils.Hasher) {
	// verify chain of tree transitions, order here is fundamental.
	api.Println("tree transition starts with RootHashBefore:", util.PrettyHex(circuit.RootHashBefore))
	root := circuit.RootHashBefore
	for i := range circuit.VotesProofs.Ballot {
		root = circuit.VotesProofs.Ballot[i].Verify(api, hFn, root)
	}
	for i := range circuit.VotesProofs.Commitment {
		root = circuit.VotesProofs.Commitment[i].Verify(api, hFn, root)
	}
	root = circuit.ResultsProofs.ResultsAdd.Verify(api, hFn, root)
	root = circuit.ResultsProofs.ResultsSub.Verify(api, hFn, root)
	api.Println("and final root is", util.PrettyHex(root), "should be equal to RootHashAfter", util.PrettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
}

func (circuit Circuit) VerifyLeafHashes(api frontend.API, hFn utils.Hasher) {
	// Process
	circuit.ProcessProofs.ID.VerifyLeafHash(api, hFn, circuit.Process.ID)
	circuit.ProcessProofs.CensusRoot.VerifyLeafHash(api, hFn, circuit.Process.CensusRoot)
	circuit.ProcessProofs.BallotMode.VerifyLeafHash(api, hFn, circuit.Process.BallotMode.Serialize()...)
	circuit.ProcessProofs.EncryptionKey.VerifyLeafHash(api, hFn, circuit.Process.EncryptionKey.Serialize()...)
	// Votes
	for i, v := range circuit.Votes {
		// Nullifier
		api.AssertIsEqual(v.Nullifier, circuit.VotesProofs.Ballot[i].NewKey)
		// Ballot
		circuit.VotesProofs.Ballot[i].VerifyNewLeafHash(api, hFn,
			v.Ballot.SerializeVars()...)
		// Address
		api.AssertIsEqual(v.Address, circuit.VotesProofs.Commitment[i].NewKey)
		// Commitment
		circuit.VotesProofs.Commitment[i].VerifyNewLeafHash(api, hFn,
			v.Commitment)
		// OverwrittenBallot
		circuit.VotesProofs.Ballot[i].VerifyOverwrittenBallot(api, hFn,
			v.OverwrittenBallot.SerializeVars()...)
	}
	// Results
	circuit.ResultsProofs.ResultsAdd.VerifyOldLeafHash(api, hFn,
		circuit.Results.OldResultsAdd.SerializeVars()...)
	circuit.ResultsProofs.ResultsSub.VerifyOldLeafHash(api, hFn,
		circuit.Results.OldResultsSub.SerializeVars()...)
	circuit.ResultsProofs.ResultsAdd.VerifyNewLeafHash(api, hFn,
		circuit.Results.NewResultsAdd.SerializeVars()...)
	circuit.ResultsProofs.ResultsSub.VerifyNewLeafHash(api, hFn,
		circuit.Results.NewResultsSub.SerializeVars()...)
}

// VerifyBallots counts the ballots using homomorphic encrpytion
func (circuit Circuit) VerifyBallots(api frontend.API) {
	ballotSum, overwrittenSum, zero := circuits.NewBallot(), circuits.NewBallot(), circuits.NewBallot()
	var ballotCount, overwrittenCount frontend.Variable = 0, 0

	for i, b := range circuit.VotesProofs.Ballot {
		ballotSum.Add(api, ballotSum,
			circuits.NewBallot().Select(api, b.IsInsertOrUpdate(api), &circuit.Votes[i].Ballot, zero))

		overwrittenSum.Add(api, overwrittenSum,
			circuits.NewBallot().Select(api, b.IsUpdate(api), &circuit.Votes[i].OverwrittenBallot, zero))

		ballotCount = api.Add(ballotCount, api.Select(b.IsInsertOrUpdate(api), 1, 0))
		overwrittenCount = api.Add(overwrittenCount, api.Select(b.IsUpdate(api), 1, 0))
	}

	circuit.Results.NewResultsAdd.AssertIsEqual(api,
		circuits.NewBallot().Add(api,
			&circuit.Results.OldResultsAdd,
			ballotSum))
	circuit.Results.NewResultsSub.AssertIsEqual(api,
		circuits.NewBallot().Add(api,
			&circuit.Results.OldResultsSub,
			overwrittenSum))
	api.AssertIsEqual(circuit.NumNewVotes, ballotCount)
	api.AssertIsEqual(circuit.NumOverwrites, overwrittenCount)
}

func (circuit Circuit) ListVotes() []circuits.Vote[frontend.Variable] {
	list := []circuits.Vote[frontend.Variable]{}
	for _, v := range circuit.Votes {
		list = append(list, v.Vote)
	}
	return list
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
		ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField(), false)
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
