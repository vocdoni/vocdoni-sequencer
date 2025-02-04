package statetransition_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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

func TestCircuitCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		statetransition.CircuitPlaceholder(),
	); err != nil {
		panic(err)
	}
}

func TestCircuitProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	s := newMockState(t)

	// first batch
	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(2, 20)); err != nil { // new vote 2
		t.Fatal(err)
	}
	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}
	witness, err := statetransitiontest.GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}
	{
		inputsHash, err := s.AggregatedWitnessHash()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := statetransition.DummyInnerProof(arbo.BytesToBigInt(inputsHash))
		if err != nil {
			t.Fatal(err)
		}
		witness.AggregatedProof = *proof
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof),
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)

	// second batch
	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(1, 100)); err != nil { // overwrite vote 1
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(3, 30)); err != nil { // add vote 3
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(4, 30)); err != nil { // add vote 4
		t.Fatal(err)
	}
	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}
	witness, err = statetransitiontest.GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}
	{
		inputsHash, err := s.AggregatedWitnessHash()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := statetransition.DummyInnerProof(arbo.BytesToBigInt(inputsHash))
		if err != nil {
			t.Fatal(err)
		}
		witness.AggregatedProof = *proof
	}
	assert.ProverSucceeded(
		statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof),
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)
}

type CircuitAggregatedWitness struct {
	statetransition.Circuit
}

func (circuit CircuitAggregatedWitness) Define(api frontend.API) error {
	circuit.VerifyAggregatedWitnessHash(api)
	return nil
}

func TestCircuitAggregatedWitnessCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}

	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitAggregatedWitness{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitAggregatedWitnessProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitAggregatedWitness{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

type CircuitAggregatedProof struct {
	statetransition.Circuit
}

func (circuit CircuitAggregatedProof) Define(api frontend.API) error {
	circuit.VerifyAggregatedProof(api)
	return nil
}

func TestCircuitAggregatedProofCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}

	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitAggregatedProof{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitAggregatedProofProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitAggregatedProof{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

type CircuitBallots struct {
	statetransition.Circuit
}

func (circuit CircuitBallots) Define(api frontend.API) error {
	circuit.VerifyBallots(api)
	return nil
}

func TestCircuitBallotsCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitBallots{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitBallotsProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitBallots{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

type CircuitMerkleProofs struct {
	statetransition.Circuit
}

func (circuit CircuitMerkleProofs) Define(api frontend.API) error {
	circuit.VerifyMerkleProofs(api, statetransition.HashFn)
	return nil
}

func TestCircuitMerkleProofsCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitMerkleProofs{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitMerkleProofsProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	debugLog(t, witness)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitMerkleProofs{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

type CircuitMerkleTransitions struct {
	statetransition.Circuit
}

func (circuit CircuitMerkleTransitions) Define(api frontend.API) error {
	circuit.VerifyMerkleTransitions(api, statetransition.HashFn)
	return nil
}

func TestCircuitMerkleTransitionsCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}

	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitMerkleTransitions{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitMerkleTransitionsProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitMerkleTransitions{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

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
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}

	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&CircuitLeafHashes{*statetransition.CircuitPlaceholder()},
	); err != nil {
		panic(err)
	}
}

func TestCircuitLeafHashesProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	witness := newMockWitness(t)
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&CircuitLeafHashes{*statetransition.CircuitPlaceholderWithProof(&witness.AggregatedProof)},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)
}

func newMockWitness(t *testing.T) *statetransition.Circuit {
	s := newMockState(t)

	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}

	if err := s.AddVote(newMockVote(1, 10)); err != nil {
		t.Fatal(err)
	}

	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}

	witness, err := statetransitiontest.GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}

	inputsHash, err := s.AggregatedWitnessHash()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := statetransition.DummyInnerProof(arbo.BytesToBigInt(inputsHash))
	if err != nil {
		t.Fatal(err)
	}
	witness.AggregatedProof = *proof
	return witness
}

func newMockState(t *testing.T) *state.State {
	s, err := state.New(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Initialize(
		util.RandomBytes(32),
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
