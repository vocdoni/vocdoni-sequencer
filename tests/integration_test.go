package tests

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

func init() {
	log.Init(log.LogLevelDebug, "stdout", nil)
}

func TestIntegration(t *testing.T) {
	c := qt.New(t)

	// Setup
	ctx := context.Background()
	api, contracts := NewTestService(t, ctx)
	_, port := api.HostPort()
	cli, err := NewTestClient(port)
	c.Assert(err, qt.IsNil)

	t.Run("create organization", func(t *testing.T) {
		orgAddr := createOrganization(c, contracts)
		t.Logf("Organization address: %s", orgAddr.String())
	})

	t.Run("create process", func(t *testing.T) {
		c := qt.New(t)

		// Create census with 10 participants
		root, participants, signers := createCensus(c, cli, 100)

		// Generate proof for first participant
		proof := generateCensusProof(c, cli, root, participants[0].Key)
		c.Assert(proof, qt.Not(qt.IsNil))
		c.Assert(proof.Siblings, qt.IsNotNil)

		// Check the proof key is the same as the participant key and signer address
		qt.Assert(t, proof.Key.String(), qt.DeepEquals, participants[0].Key.String())
		qt.Assert(t, string(proof.Key), qt.DeepEquals, string(signers[0].Address().Bytes()))

		ballotMode := types.BallotMode{
			MaxCount:        2,
			MaxValue:        new(types.BigInt).SetUint64(100),
			MinValue:        new(types.BigInt).SetUint64(0),
			ForceUniqueness: false,
			CostFromWeight:  false,
			CostExponent:    1,
			MaxTotalCost:    new(types.BigInt).SetUint64(100),
			MinTotalCost:    new(types.BigInt).SetUint64(100),
		}

		pid := createProcess(c, contracts, cli, root, ballotMode)
		t.Logf("Process ID: %s", pid.String())
	})
}
