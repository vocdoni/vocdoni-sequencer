package statetransition_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	statetransitiontest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"github.com/vocdoni/vocdoni-z-sandbox/util"

	"github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db/metadb"
)

func testCircuitCompile(t *testing.T, c frontend.Circuit) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	if _, err := frontend.Compile(circuits.StateTransitionCurve.ScalarField(), r1cs.NewBuilder, c); err != nil {
		panic(err)
	}
}

func testCircuitProve(t *testing.T, circuit, witness frontend.Circuit) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		circuit,
		witness,
		test.WithCurves(circuits.StateTransitionCurve),
		test.WithBackends(backend.GROTH16))
}

func TestCircuitCompile(t *testing.T) {
	testCircuitCompile(t, statetransition.CircuitPlaceholder())
}

func TestCircuitProve(t *testing.T) {
	s := newMockState(t)
	{
		witness := newMockTransitionWithVotes(t, s,
			newMockVote(1, 10), // add vote 1
			newMockVote(2, 20), // add vote 2
		)
		testCircuitProve(t, statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK), witness)

		debugLog(t, witness)
	}
	{
		witness := newMockTransitionWithVotes(t, s,
			newMockVote(1, 100), // overwrite vote 1
			newMockVote(3, 30),  // add vote 3
			newMockVote(4, 40),  // add vote 4
		)
		testCircuitProve(t, statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK), witness)

		debugLog(t, witness)
	}
}

type CircuitCalculateAggregatorWitness struct {
	statetransition.Circuit
}

func (circuit CircuitCalculateAggregatorWitness) Define(api frontend.API) error {
	_, err := circuit.CalculateAggregatorWitness(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create bw6761 witness: ", err)
	}
	return nil
}

func TestCircuitCalculateAggregatorWitnessCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitCalculateAggregatorWitness{*statetransition.CircuitPlaceholder()})
}

func TestCircuitCalculateAggregatorWitnessProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitCalculateAggregatorWitness{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)
}

type CircuitAggregatorProof struct {
	statetransition.Circuit
}

func (circuit CircuitAggregatorProof) Define(api frontend.API) error {
	circuit.VerifyAggregatorProof(api)
	return nil
}

func TestCircuitAggregatorProofCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitAggregatorProof{*statetransition.CircuitPlaceholder()})
}

func TestCircuitAggregatorProofProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitAggregatorProof{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)
}

type CircuitBallots struct {
	statetransition.Circuit
}

func (circuit CircuitBallots) Define(api frontend.API) error {
	circuit.VerifyBallots(api)
	return nil
}

func TestCircuitBallotsCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitBallots{*statetransition.CircuitPlaceholder()})
}

func TestCircuitBallotsProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitBallots{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)
}

type CircuitMerkleProofs struct {
	statetransition.Circuit
}

func (circuit CircuitMerkleProofs) Define(api frontend.API) error {
	circuit.VerifyMerkleProofs(api, statetransition.HashFn)
	return nil
}

func TestCircuitMerkleProofsCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitMerkleProofs{*statetransition.CircuitPlaceholder()})
}

func TestCircuitMerkleProofsProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitMerkleProofs{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)
}

type CircuitMerkleTransitions struct {
	statetransition.Circuit
}

func (circuit CircuitMerkleTransitions) Define(api frontend.API) error {
	circuit.VerifyMerkleTransitions(api, statetransition.HashFn)
	return nil
}

func TestCircuitMerkleTransitionsCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitMerkleTransitions{*statetransition.CircuitPlaceholder()})
}

func TestCircuitMerkleTransitionsProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitMerkleTransitions{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)

	debugLog(t, witness)
}

type CircuitLeafHashes struct {
	statetransition.Circuit
}

func (circuit CircuitLeafHashes) Define(api frontend.API) error {
	circuit.VerifyLeafHashes(api, statetransition.HashFn)
	return nil
}

func TestCircuitLeafHashesCompile(t *testing.T) {
	testCircuitCompile(t, &CircuitLeafHashes{*statetransition.CircuitPlaceholder()})
}

func TestCircuitLeafHashesProve(t *testing.T) {
	witness := newMockWitness(t)
	testCircuitProve(t, &CircuitLeafHashes{
		*statetransition.CircuitPlaceholderWithProof(&witness.AggregatorProof, &witness.AggregatorVK),
	}, witness)

	debugLog(t, witness)
}

func newMockTransitionWithVotes(t *testing.T, s *state.State, votes ...*state.Vote) *statetransition.Circuit {
	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}

	for _, v := range votes {
		if err := s.AddVote(v); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}

	witness, err := statetransitiontest.GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}

	inputsHash, err := s.AggregatorWitnessHash()
	if err != nil {
		t.Fatal(err)
	}

	proof, vk, err := statetransition.DummyInnerProof(inputsHash)
	if err != nil {
		t.Fatal(err)
	}
	witness.AggregatorProof = *proof
	witness.AggregatorVK = *vk
	return witness
}

func newMockWitness(t *testing.T) *statetransition.Circuit {
	return newMockTransitionWithVotes(t, newMockState(t), newMockVote(1, 10))
}

func newMockState(t *testing.T) *state.State {
	s, err := state.New(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Initialize(
		util.RandomBytes(16),
		circuits.MockBallotMode().Bytes(),
		circuits.MockEncryptionKey().Bytes(),
	); err != nil {
		t.Fatal(err)
	}

	return s
}

const (
	mockNullifiersOffset = 100
	mockAddressesOffset  = 200
	// maxKeyLen is ceil(maxLevels/8)
	maxKeyLen = (circuits.StateProofMaxLevels + 7) / 8
)

// newMockVote creates a new vote
func newMockVote(index, amount int64) *state.Vote {
	nullifier := arbo.BigIntToBytes(maxKeyLen,
		big.NewInt(int64(index)+int64(mockNullifiersOffset))) // mock

	// generate a public mocked key
	publicKey, _, err := elgamal.GenerateKey(state.Curve)
	if err != nil {
		panic(fmt.Errorf("error generating public key: %v", err))
	}

	fields := [circuits.FieldsPerBallot]*big.Int{}
	for i := range fields {
		fields[i] = big.NewInt(int64(amount + int64(i)))
	}

	ballot, err := elgamal.NewBallot(publicKey).Encrypt(fields, publicKey, nil)
	if err != nil {
		panic(fmt.Errorf("error encrypting: %v", err))
	}

	address := arbo.BigIntToBytes(maxKeyLen,
		big.NewInt(int64(index)+int64(mockAddressesOffset))) // mock
	commitment := big.NewInt(amount + 256)

	return &state.Vote{
		Nullifier:  nullifier,
		Ballot:     ballot,
		Address:    address,
		Commitment: commitment,
	}
}

func debugLog(t *testing.T, witness *statetransition.Circuit) {
	// js, _ := json.MarshalIndent(witness, "", "  ")
	// fmt.Printf("\n\n%s\n\n", js)
	t.Log("public: RootHashBefore", util.PrettyHex(witness.RootHashBefore))
	t.Log("public: RootHashAfter", util.PrettyHex(witness.RootHashAfter))
	t.Log("public: NumVotes", util.PrettyHex(witness.NumNewVotes))
	t.Log("public: NumOverwrites", util.PrettyHex(witness.NumOverwrites))
	for name, mts := range map[string][circuits.VotesPerBatch]statetransition.MerkleTransition{
		"Ballot":     witness.VotesProofs.Ballot,
		"Commitment": witness.VotesProofs.Commitment,
	} {
		for _, mt := range mts {
			t.Log(name, "transitioned", "(root", util.PrettyHex(mt.OldRoot), "->", util.PrettyHex(mt.NewRoot), ")",
				"value", util.PrettyHex(mt.OldLeafHash), "->", util.PrettyHex(mt.NewLeafHash),
			)
		}
	}

	for name, mt := range map[string]statetransition.MerkleTransition{
		"ResultsAdd": witness.ResultsProofs.ResultsAdd,
		"ResultsSub": witness.ResultsProofs.ResultsSub,
	} {
		t.Log(name, "transitioned", "(root", util.PrettyHex(mt.OldRoot), "->", util.PrettyHex(mt.NewRoot), ")",
			"value", util.PrettyHex(mt.OldLeafHash), "->", util.PrettyHex(mt.NewLeafHash),
		)
	}
}
