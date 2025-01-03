package voteverifiertest

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
)

func TestVerifySingleVoteCircuit(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	// generate voter account
	privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
	c.Assert(err, qt.IsNil)
	_, placeholder, assigments, err := VoteVerifierInputsForTest([]VoterTestData{
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
	assert.SolvingSucceeded(&placeholder, &assigments[0],
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
	_, placeholder, assigments, err := VoteVerifierInputsForTest(data, nil)
	c.Assert(err, qt.IsNil)
	assert := test.NewAssert(t)
	now := time.Now()
	for i, assigment := range assigments {
		c.Logf("proof %d of %d", i+1, len(assigments))
		err := test.IsSolved(&placeholder, &assigment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
	}
	fmt.Println("proving tooks", time.Since(now))
}
