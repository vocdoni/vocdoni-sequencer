package voteverifier

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	circomtest "github.com/vocdoni/vocdoni-z-sandbox/circuits/circom"
)

func TestVerifyVoteCircuit(t *testing.T) {
	c := qt.New(t)
	// generate voter account
	privKey, pubKey, address, err := circomtest.GenerateECDSAaccount()
	c.Assert(err, qt.IsNil)
	_, placeholder, assigments, err := GenerateInputs([]VoterData{
		{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		},
	})
	c.Assert(err, qt.IsNil)
	// generate proof
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&placeholder, &assigments[0],
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16))
	fmt.Println("proving tooks", time.Since(now))
}

func TestMultipleVerifyVoteCircuit(t *testing.T) {
	c := qt.New(t)
	data := []VoterData{}
	for i := 0; i < 10; i++ {
		// generate voter account
		privKey, pubKey, address, err := circomtest.GenerateECDSAaccount()
		c.Assert(err, qt.IsNil)
		data = append(data, VoterData{privKey, pubKey, address})
	}
	_, placeholder, assigments, err := GenerateInputs(data)
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
