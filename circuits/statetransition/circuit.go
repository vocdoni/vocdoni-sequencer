package statetransition

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

var (
	HashFn      = utils.MiMCHasher
	HashFnMiMC7 = MiMC7Hasher // TODO: move this to gnark-crypto-primitives/utils
)

// MiMC7Hasher is a hash function that hashes the data provided using the
// mimc hash function and the current compiler field. It is used to hash the
// leaves of the census tree during the proof verification.
func MiMC7Hasher(api frontend.API, data ...emulated.Element[sw_bn254.ScalarField]) (emulated.Element[sw_bn254.ScalarField], error) {
	h, err := mimc7.NewMiMC(api)
	if err != nil {
		return emulated.Element[sw_bn254.ScalarField]{}, err
	}
	h.Write(data...)
	return h.Sum(), nil
}

type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumNewVotes    frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS
	Process circuits.Process[emulated.Element[sw_bn254.ScalarField]]
	Votes   [circuits.VotesPerBatch]circuits.Vote[emulated.Element[sw_bn254.ScalarField]]

	ProcessIDProof     MerkleProof
	CensusRootProof    MerkleProof
	BallotModeProof    MerkleProof
	EncryptionKeyProof MerkleProof
	ResultsAdd         MerkleTransition
	ResultsSub         MerkleTransition
	Ballot             [circuits.VotesPerBatch]MerkleTransition
	Commitment         [circuits.VotesPerBatch]MerkleTransition

	AggregatedProof circuits.InnerProofBW6761
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	circuit.VerifyAggregatedWitnessHash(api)
	circuit.VerifyAggregatedProof(api)
	circuit.VerifyMerkleProofs(api, HashFn)
	circuit.VerifyMerkleTransitions(api, HashFn)
	circuit.VerifyBallots(api)
	return nil
}

func (circuit Circuit) VerifyAggregatedWitnessHash(api frontend.API) {
	api.AssertIsEqual(len(circuit.AggregatedProof.Witness.Public), 1)
	publicInput, err := utils.PackScalarToVar(api, circuit.AggregatedProof.Witness.Public[0])
	if err != nil {
		circuits.FrontendError(api, "failed to pack scalar to var: ", err)
	}
	hash, err := HashFnMiMC7(api, circuits.AggregatedWitnessInputs(api, circuit.Process, circuit.Votes[:])...)
	if err != nil {
		circuits.FrontendError(api, "failed to hash: ", err)
	}
	hashVar, err := utils.PackScalarToVar(api, hash)
	if err != nil {
		circuits.FrontendError(api, "failed to pack scalar to variable", err)
	}
	api.AssertIsEqual(hashVar, publicInput)
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
	circuit.ProcessIDProof.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.CensusRootProof.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.BallotModeProof.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.EncryptionKeyProof.VerifyProof(api, hFn, circuit.RootHashBefore)
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
	ballotSum, overwrittenSum, zero := circuits.NewBallot(), circuits.NewBallot(), circuits.NewBallot()
	var ballotCount, overwrittenCount frontend.Variable = 0, 0

	for _, b := range circuit.Ballot {
		ballotSum.Add(api, ballotSum,
			circuits.NewBallot().Select(api, b.IsInsertOrUpdate(api), &b.NewCiphertexts, zero))

		overwrittenSum.Add(api, overwrittenSum,
			circuits.NewBallot().Select(api, b.IsUpdate(api), &b.OldCiphertexts, zero))

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
