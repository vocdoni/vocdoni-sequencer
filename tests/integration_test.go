package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
	"github.com/vocdoni/vocdoni-z-sandbox/web3"
)

func createCensus(c *qt.C, cli *client.HTTPclient, size int) ([]byte, []*api.CensusParticipant) {
	// Create a new census
	body, code, err := cli.Request(http.MethodPost, nil, nil, "census")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK)

	var resp api.NewCensus
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&resp)
	c.Assert(err, qt.IsNil)

	// Generate random participants
	censusParticipants := api.CensusParticipants{Participants: []*api.CensusParticipant{}}
	for i := 0; i < size; i++ {
		key := util.RandomBytes(30)
		censusParticipants.Participants = append(censusParticipants.Participants, &api.CensusParticipant{
			Key:    key,
			Weight: new(types.BigInt).SetUint64(1),
		})
	}

	// Add participants to census
	_, code, err = cli.Request(http.MethodPost, censusParticipants, []string{"id", resp.Census.String()}, "census", "participants")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK)

	// Get census root
	body, code, err = cli.Request(http.MethodGet, nil, []string{"id", resp.Census.String()}, "census", "root")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK)

	var rootResp api.CensusRoot
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&rootResp)
	c.Assert(err, qt.IsNil)

	return rootResp.Root, censusParticipants.Participants
}

func generateCensusProof(c *qt.C, cli *client.HTTPclient, root []byte, key []byte) []byte {
	// Get proof for the key
	body, code, err := cli.Request(http.MethodGet, nil, []string{
		"root", hex.EncodeToString(root),
		"key", hex.EncodeToString(key),
	}, "census", "proof")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK)

	var proof types.CensusProof
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&proof)
	c.Assert(err, qt.IsNil)

	return proof.Siblings
}

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
		root, participants := createCensus(c, cli, 10)

		// Generate proof for first participant
		proof := generateCensusProof(c, cli, root, participants[0].Key)
		c.Assert(proof, qt.Not(qt.IsNil))
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

func createOrganization(c *qt.C, contracts *web3.Contracts) common.Address {
	orgAddr := contracts.AccountAddress()
	txHash, err := contracts.CreateOrganization(orgAddr, &types.OrganizationInfo{
		Name:        fmt.Sprintf("Vocdoni test %x", orgAddr[:4]),
		MetadataURI: "https://vocdoni.io",
	})
	c.Assert(err, qt.IsNil)

	err = contracts.WaitTx(txHash, time.Second*30)
	c.Assert(err, qt.IsNil)
	return orgAddr
}

func createProcess(c *qt.C, contracts *web3.Contracts, cli *client.HTTPclient, censusRoot []byte, ballotMode types.BallotMode) *types.ProcessID {
	// Create test process request
	nonce, err := contracts.AccountNonce()
	c.Assert(err, qt.IsNil)

	// Sign the process creation request
	signature, err := contracts.SignMessage([]byte(fmt.Sprintf("%d%d", contracts.ChainID, nonce)))
	c.Assert(err, qt.IsNil)

	process := &types.ProcessSetup{
		CensusRoot: censusRoot,
		BallotMode: ballotMode,
		Nonce:      nonce,
		ChainID:    uint32(contracts.ChainID),
		Signature:  signature,
	}

	body, code, err := cli.Request(http.MethodPost, process, nil, "process")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK, qt.Commentf("response body %s", string(body)))

	var resp types.ProcessSetupResponse
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&resp)
	c.Assert(err, qt.IsNil)
	c.Assert(resp.ProcessID, qt.Not(qt.IsNil))
	c.Assert(resp.EncryptionPubKey[0], qt.Not(qt.IsNil))
	c.Assert(resp.EncryptionPubKey[1], qt.Not(qt.IsNil))

	pid, txHash, err := contracts.CreateProcess(&types.Process{
		Status:         0,
		OrganizationId: contracts.AccountAddress(),
		EncryptionKey: &types.EncryptionKey{
			X: (*big.Int)(&resp.EncryptionPubKey[0]),
			Y: (*big.Int)(&resp.EncryptionPubKey[1]),
		},
		StateRoot:   resp.StateRoot,
		StartTime:   time.Now().Add(30 * time.Second),
		Duration:    time.Hour,
		MetadataURI: "https://example.com/metadata",
		BallotMode:  &ballotMode,
		Census: &types.Census{
			CensusRoot:   censusRoot,
			MaxVotes:     new(types.BigInt).SetUint64(1000),
			CensusURI:    "https://example.com/census",
			CensusOrigin: 0,
		},
	})
	c.Assert(err, qt.IsNil)

	err = contracts.WaitTx(*txHash, time.Second*15)
	c.Assert(err, qt.IsNil)

	return pid
}
