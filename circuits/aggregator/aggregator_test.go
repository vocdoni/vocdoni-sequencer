package aggregator

import (
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func TestAggregatorCircuit(t *testing.T) {
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	_, placeholder, assigments, err := GenInputsForTest(processId, 3)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(placeholder, assigments,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	c.Logf("proving tooks %s", time.Since(now).String())
}

func TestAggregatorCircuitGenArtifact(t *testing.T) {
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	_, placeholder, assigments, err := GenInputsForTest(processId, 3)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()

	// 0. Compile
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, placeholder)
	c.Assert(err, qt.IsNil)

	// 1. One time setup
	pk, vk, err := groth16.Setup(cs)
	c.Assert(err, qt.IsNil)

	// 2. Proof creation
	witness, _ := frontend.NewWitness(assigments, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(cs, pk, witness)
	c.Assert(err, qt.IsNil)

	// 2.a. Public witness
	publicWitness, err := witness.Public()
	c.Assert(err, qt.IsNil)

	// 3. Proof verification
	err = groth16.Verify(proof, vk, publicWitness)
	c.Assert(err, qt.IsNil)

	c.Logf("proving tooks %s", time.Since(now).String())
}
