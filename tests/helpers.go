package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/frankban/quicktest"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/service"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
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
	quicktest.Assert(t, err, quicktest.IsNil)
	t.Cleanup(func() {
		err := compose.Down(ctx, tc.RemoveOrphans(true), tc.RemoveVolumes(true))
		quicktest.Assert(t, err, quicktest.IsNil)
	})
	ctx2, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	err = compose.Up(ctx2, tc.Wait(true))
	quicktest.Assert(t, err, quicktest.IsNil)

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
	quicktest.Assert(t, err, quicktest.IsNil)
	t.Cleanup(api.Stop)

	return api, contracts
}
