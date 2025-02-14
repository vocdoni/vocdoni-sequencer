package voteverifiertest

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto"
)

func TestVerifyExternalInputs(t *testing.T) {
	assert := test.NewAssert(t)
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	assert.NoError(err)

	bCircomProof, err := os.ReadFile("/home/lucasmenendez/vocdoni-z-sandbox/tests/debug_proof.json")
	assert.NoError(err)
	t.Log(string(bCircomProof))
	bCircomPubInputs, err := os.ReadFile("/home/lucasmenendez/vocdoni-z-sandbox/tests/debug_pub_inputs.json")
	assert.NoError(err)
	t.Log(string(bCircomPubInputs))

	recursiveProof, err := circuits.Circom2GnarkProofForRecursion(ballottest.TestCircomVerificationKey, string(bCircomProof), string(bCircomPubInputs))
	assert.NoError(err)

	bInputs, err := os.ReadFile("/home/lucasmenendez/vocdoni-z-sandbox/tests/debug_inputs.json")
	assert.NoError(err)
	t.Log(string(bInputs))
	debugInputs := api.DebugVoteVerifierInputs{}
	assert.NoError(json.Unmarshal(bInputs, &debugInputs))

	encKey := circuits.EncryptionKey[*big.Int]{
		PubKey: [2]*big.Int{
			debugInputs.EncryptionKeyX.BigInt().MathBigInt(),
			debugInputs.EncryptionKeyY.BigInt().MathBigInt(),
		},
	}
	censusSiblings := [160]emulated.Element[sw_bn254.ScalarField]{}
	for i, sibling := range debugInputs.CensusSiblings {
		censusSiblings[i] = emulated.ValueOf[sw_bn254.ScalarField](sibling.BigInt().MathBigInt())
	}
	assignment := voteverifier.VerifyVoteCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](debugInputs.InputHash.BigInt().MathBigInt()),
		Vote: circuits.EmulatedVote[sw_bn254.ScalarField]{
			Address:    emulated.ValueOf[sw_bn254.ScalarField](debugInputs.Address.BigInt().MathBigInt()),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](debugInputs.Commitment.BigInt().MathBigInt()),
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](debugInputs.Nullifier.BigInt().MathBigInt()),
			Ballot:     *debugInputs.Ballot.ToGnarkEmulatedBN254(),
		},
		UserWeight: emulated.ValueOf[sw_bn254.ScalarField](debugInputs.Weight.BigInt().MathBigInt()),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:            emulated.ValueOf[sw_bn254.ScalarField](debugInputs.ProcessID.BigInt().MathBigInt()),
			CensusRoot:    emulated.ValueOf[sw_bn254.ScalarField](debugInputs.CensusRoot.BigInt().MathBigInt()),
			EncryptionKey: encKey.BigIntsToEmulatedElementBN254(),
			BallotMode:    circuits.MockBallotModeEmulated(),
		},
		CensusSiblings: censusSiblings,
		Msg:            emulated.ValueOf[emulated.Secp256k1Fr](crypto.SignatureHash(debugInputs.Msg.BigInt().MathBigInt(), circuits.VoteVerifierCurve.ScalarField())),
		PublicKey: gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](debugInputs.PublicKeyX.BigInt().MathBigInt()),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](debugInputs.PublicKeyY.BigInt().MathBigInt()),
		},
		Signature: gnarkecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](debugInputs.SignatureR.BigInt().MathBigInt()),
			S: emulated.ValueOf[emulated.Secp256k1Fr](debugInputs.SignatureS.BigInt().MathBigInt()),
		},
		CircomProof: recursiveProof.Proof,
	}
	// generate proof
	now := time.Now()
	assert.SolvingSucceeded(&voteverifier.VerifyVoteCircuit{
		CircomProof:           circomPlaceholder.Proof,
		CircomVerificationKey: circomPlaceholder.Vk,
	}, &assignment,
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16))
	fmt.Println("proving tooks", time.Since(now))
}

func TestVerifySingleVoteCircuit(t *testing.T) {
	c := qt.New(t)
	// generate voter account
	privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)
	_, placeholder, assignments, err := VoteVerifierInputsForTest([]VoterTestData{
		{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		},
	}, nil)
	c.Assert(err, qt.IsNil)
	// generate proof
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&placeholder, &assignments[0],
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16))
	fmt.Println("proving tooks", time.Since(now))
}

func TestVerifyMultipleVotesCircuit(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	data := []VoterTestData{}
	for i := 0; i < 10; i++ {
		// generate voter account
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		c.Assert(err, qt.IsNil)
		data = append(data, VoterTestData{privKey, pubKey, address})
	}
	_, placeholder, assignments, err := VoteVerifierInputsForTest(data, nil)
	c.Assert(err, qt.IsNil)
	assert := test.NewAssert(t)
	now := time.Now()
	for i, assignment := range assignments {
		c.Logf("proof %d of %d", i+1, len(assignments))
		err := test.IsSolved(&placeholder, &assignment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
	}
	fmt.Println("proving tooks", time.Since(now))
}
