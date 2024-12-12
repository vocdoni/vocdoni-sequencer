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
