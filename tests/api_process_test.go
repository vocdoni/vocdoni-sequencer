package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func init() {
	log.Init(log.LogLevelDebug, "stdout", nil)
}

func TestProcess(t *testing.T) {
	c := qt.New(t)

	// Setup
	tmpDir := t.TempDir()
	api, err := SetupAPI(tmpDir)
	c.Assert(err, qt.IsNil)

	signer, err := NewTestSigner()
	c.Assert(err, qt.IsNil)

	_, port := api.HostPort()
	cli, err := NewTestClient(port)
	c.Assert(err, qt.IsNil)

	t.Run("create process", func(t *testing.T) {
		c := qt.New(t)

		// Create process
		resp := CreateTestProcess(c, cli, signer)
		c.Assert(resp.ProcessID, qt.Not(qt.IsNil))
		c.Assert(resp.EncryptionPubKey[0], qt.Not(qt.IsNil))
		c.Assert(resp.EncryptionPubKey[1], qt.Not(qt.IsNil))
	})
}

// CreateTestProcess creates a test process with the given parameters.
// It returns the process response and any error encountered.
func CreateTestProcess(c *qt.C, cli *client.HTTPclient, signer *ethereum.SignKeys) api.ProcessResponse {
	// Create test process request
	nonce := uint64(1)
	chainID := uint32(1)
	censusRoot := util.RandomBytes(32)

	// Sign the process creation request
	msg := []byte(fmt.Sprintf("%d%d", chainID, nonce))
	signature, err := signer.SignEthereum(msg)
	c.Assert(err, qt.IsNil)

	process := &api.Process{
		CensusRoot: censusRoot,
		BallotMode: types.BallotMode{
			MaxCount:        5,
			ForceUniqueness: true,
			MaxValue:        toBigInt(100),
			MinValue:        toBigInt(0),
			MaxTotalCost:    toBigInt(500),
			MinTotalCost:    toBigInt(5),
			CostExponent:    1,
			CostFromWeight:  false,
		},
		Nonce:     nonce,
		ChainID:   chainID,
		Signature: signature,
	}

	body, code, err := cli.Request(http.MethodPost, process, nil, "process")
	c.Assert(err, qt.IsNil)
	c.Assert(code, qt.Equals, http.StatusOK, qt.Commentf("response body %s", string(body)))

	var resp api.ProcessResponse
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&resp)
	c.Assert(err, qt.IsNil)
	return resp
}
