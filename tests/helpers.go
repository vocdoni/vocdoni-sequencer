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
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/service"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
	"github.com/vocdoni/vocdoni-z-sandbox/web3"
)

const testLocalAccountPrivKey = "0cebebc37477f513cd8f946ffced46e368aa4f9430250ce4507851edbba86b20" // defined in docker/files/genesis.json

// setupAPI creates and starts a new API server for testing.
// It returns the server port.
func setupAPI(ctx context.Context, db *storage.Storage) (*service.APIService, error) {
	tmpPort := util.RandomInt(40000, 60000)

	api := service.NewAPI(db, "127.0.0.1", tmpPort)
	if err := api.Start(ctx); err != nil {
		return nil, err
	}

	// Wait for the HTTP server to start
	time.Sleep(500 * time.Millisecond)
	return api, nil
}

// NewTestClient creates a new API client for testing.
func NewTestClient(port int) (*client.HTTPclient, error) {
	return client.New(fmt.Sprintf("http://127.0.0.1:%d", port))
}

func NewTestService(t *testing.T, ctx context.Context) (*service.APIService, *web3.Contracts) {
	log.Infow("starting Geth docker compose")
	compose, err := tc.NewDockerCompose("docker/docker-compose.yml")
	qt.Assert(t, err, qt.IsNil)
	t.Cleanup(func() {
		err := compose.Down(ctx, tc.RemoveOrphans(true), tc.RemoveVolumes(true))
		qt.Assert(t, err, qt.IsNil)
	})
	ctx2, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	err = compose.Up(ctx2, tc.Wait(true))
	qt.Assert(t, err, qt.IsNil)

	log.Infow("deploying contracts")
	contracts, err := web3.DeployContracts("http://localhost:8545", testLocalAccountPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Infow("contracts deployed", "chainId", contracts.ChainID)

	kv := memdb.New()
	stg := storage.New(kv)

	pm := service.NewProcessMonitor(contracts, stg, time.Second*2)
	if err := pm.Start(ctx); err != nil {
		log.Fatal(err)
	}
	t.Cleanup(pm.Stop)

	api, err := setupAPI(ctx, stg)
	qt.Assert(t, err, qt.IsNil)
	t.Cleanup(api.Stop)

	return api, contracts
}

func createCensus(c *qt.C, cli *client.HTTPclient, size int) ([]byte, []*api.CensusParticipant, []*ethereum.SignKeys) {
	// Create a new census
	body, code, err := cli.Request(http.MethodPost, nil, nil, "census")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK)

	var resp api.NewCensus
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&resp)
	c.Assert(err, qt.IsNil)

	// Generate random participants
	signers := []*ethereum.SignKeys{}
	censusParticipants := api.CensusParticipants{Participants: []*api.CensusParticipant{}}
	for i := 0; i < size; i++ {
		signer := ethereum.NewSignKeys()
		if err := signer.Generate(); err != nil {
			c.Fatalf("failed to generate signer: %v", err)
		}
		key := signer.Address().Bytes()
		censusParticipants.Participants = append(censusParticipants.Participants, &api.CensusParticipant{
			Key:    key,
			Weight: new(types.BigInt).SetUint64(1),
		})
		signers = append(signers, signer)
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

	return rootResp.Root, censusParticipants.Participants, signers
}

func generateCensusProof(c *qt.C, cli *client.HTTPclient, root []byte, key []byte) *types.CensusProof {
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

	return &proof
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
