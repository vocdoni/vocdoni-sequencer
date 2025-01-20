package aggregator_test

import (
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	aggregatortest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func TestCircuitCompile(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder,
		aggregator.CircuitPlaceholder())
	if err != nil {
		panic(err)
	}
}

func TestCircuitProve(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	_, placeholder, assigments, err := aggregatortest.AggregarorInputsForTest(processId, 3)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation tooks %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.CheckCircuit(&placeholder,
		test.WithValidAssignment(assigments),
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
	// assert.ProverSucceeded(
	// 	&statetransition.Circuit{},
	// 	witness,
	// 	test.WithCurves(ecc.BN254),
	// 	test.WithBackends(backend.GROTH16))

	c.Logf("proving tooks %s", time.Since(now).String())
}
