package tests

import (
	"fmt"
	"time"

	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

// toBigInt converts an int64 to a *types.BigInt
func toBigInt(i int64) *types.BigInt {
	bi := new(types.BigInt)
	bi.UnmarshalText([]byte(fmt.Sprintf("%d", i)))
	return bi
}

// SetupAPI creates and starts a new API server for testing.
// It returns the server port.
func SetupAPI(tmpDir string) (int, error) {
	tmpPort := util.RandomInt(40000, 60000)

	_, err := api.New(&api.APIConfig{
		Host:    "127.0.0.1",
		Port:    tmpPort,
		DataDir: tmpDir,
	})
	if err != nil {
		return 0, err
	}

	// Wait for the HTTP server to start
	time.Sleep(500 * time.Millisecond)
	return tmpPort, nil
}

// NewTestSigner creates and initializes a new ethereum signer for testing.
func NewTestSigner() (*ethereum.SignKeys, error) {
	signer := ethereum.NewSignKeys()
	if err := signer.Generate(); err != nil {
		return nil, err
	}
	return signer, nil
}

// NewTestClient creates a new API client for testing.
func NewTestClient(port int) (*client.HTTPclient, error) {
	return client.New(fmt.Sprintf("http://127.0.0.1:%d", port))
}
