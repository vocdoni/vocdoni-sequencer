package tests

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
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
	apiSrv, contracts := NewTestService(t, ctx)
	_, port := apiSrv.HostPort()
	cli, err := NewTestClient(port)
	c.Assert(err, qt.IsNil)

	c.Run("create organization", func(c *qt.C) {
		orgAddr := createOrganization(c, contracts)
		t.Logf("Organization address: %s", orgAddr.String())
	})

	c.Run("create process", func(c *qt.C) {
		// Create census with 10 participants
		root, participants, signers := createCensus(c, cli, 10)

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

		pid, _ := createProcess(c, contracts, cli, root, ballotMode)
		t.Logf("Process ID: %s", pid.String())
	})

	c.Run("create vote", func(c *qt.C) {
		// create census with 10 participants
		root, participants, signers := createCensus(c, cli, 10)
		// create process
		mockMode := circuits.MockBallotMode()
		ballotMode := types.BallotMode{
			MaxCount:        uint8(mockMode.MaxCount.Uint64()),
			ForceUniqueness: mockMode.ForceUniqueness.Uint64() == 1,
			MaxValue:        (*types.BigInt)(mockMode.MaxValue),
			MinValue:        (*types.BigInt)(mockMode.MaxValue),
			MaxTotalCost:    (*types.BigInt)(mockMode.MaxTotalCost),
			MinTotalCost:    (*types.BigInt)(mockMode.MinTotalCost),
			CostFromWeight:  mockMode.CostFromWeight.Uint64() == 1,
			CostExponent:    uint8(mockMode.CostExp.Uint64()),
		}
		pid, encryptionKey := createProcess(c, contracts, cli, root, ballotMode)
		// generate a vote for the first participant
		vote := createVote(c, pid, encryptionKey, participants[0].Key, signers[0])
		// generate census proof for first participant
		censusProof := generateCensusProof(c, cli, root, participants[0].Key)
		c.Assert(censusProof, qt.Not(qt.IsNil))
		c.Assert(censusProof.Siblings, qt.IsNotNil)
		vote.CensusProof = *censusProof

		body, status, err := cli.Request("POST", vote, nil, api.VotesEndpoint)
		c.Assert(err, qt.IsNil)
		c.Assert(status, qt.Equals, 200)
		c.Log("Vote created", string(body))
	})
}
