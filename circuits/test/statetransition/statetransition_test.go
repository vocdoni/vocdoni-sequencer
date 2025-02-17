package statetransitiontest

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func TestStateTransitionCircuit(t *testing.T) {
	if os.Getenv("RUN_CIRCUIT_TESTS") == "" || os.Getenv("RUN_CIRCUIT_TESTS") == "false" {
		t.Skip("skipping circuit tests...")
	}
	c := qt.New(t)
	// inputs generation
	now := time.Now()
	processId := util.RandomBytes(20)
	fmt.Println("start") // debug
	_, placeholder, assignments, err := StateTransitionInputsForTest(processId, 3)
	c.Assert(err, qt.IsNil)
	c.Logf("inputs generation took %s", time.Since(now).String())
	// proving
	now = time.Now()
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(placeholder, assignments,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		// test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())),
	)
	c.Logf("proving took %s", time.Since(now).String())
}
