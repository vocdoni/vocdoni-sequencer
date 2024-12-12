package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/api/client"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

func toBigInt(i int64) *types.BigInt {
	bi := new(types.BigInt)
	bi.UnmarshalText([]byte(fmt.Sprintf("%d", i)))
	return bi
}

func init() {
	log.Init(log.LogLevelDebug, "stdout", nil)
}

func TestProcess(t *testing.T) {
	c := qt.New(t)

	// Setup
	tmpDir := t.TempDir()
	// choose a random port for the API server
	tmpPort := util.RandomInt(40000, 60000)

	_, err := api.New(&api.APIConfig{
		Host:    "127.0.0.1",
		Port:    tmpPort,
		DataDir: tmpDir,
	})
	c.Assert(err, qt.IsNil)

	// Wait for the HTTP server to start
	time.Sleep(1 * time.Second)

	signer := ethereum.NewSignKeys()
	c.Assert(signer.Generate(), qt.IsNil)

	cli, err := client.New(fmt.Sprintf("http://127.0.0.1:%d", tmpPort))
	c.Assert(err, qt.IsNil)

	// Helper function to create a test process
	createTestProcess := func(c *qt.C) api.ProcessResponse {
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
			BallotMode: api.BallotMode{
				MaxCount:        5,
				ForceUniqueness: true,
				MaxValue:        *toBigInt(100),
				MinValue:        *toBigInt(0),
				MaxTotalCost:    *toBigInt(500),
				MinTotalCost:    *toBigInt(5),
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

	t.Run("create process", func(t *testing.T) {
		c := qt.New(t)

		// Create process
		resp := createTestProcess(c)
		c.Assert(resp.ProcessID, qt.Not(qt.IsNil))
		c.Assert(resp.EncryptionPubKey[0], qt.Not(qt.IsNil))
		c.Assert(resp.EncryptionPubKey[1], qt.Not(qt.IsNil))

		// Retrieve process
		body, code, err := cli.Request(http.MethodGet, nil, []string{"id", resp.ProcessID.String()}, "process")
		c.Assert(err, qt.IsNil)
		c.Assert(code, qt.Equals, http.StatusOK, qt.Commentf("response body %s", string(body)))

		var getResp api.ProcessResponse
		err = json.NewDecoder(bytes.NewReader(body)).Decode(&getResp)
		c.Assert(err, qt.IsNil)
		c.Assert(getResp.ProcessID, qt.DeepEquals, resp.ProcessID)
		c.Assert(getResp.EncryptionPubKey[0].String(), qt.DeepEquals, resp.EncryptionPubKey[0].String())
		c.Assert(getResp.EncryptionPubKey[1].String(), qt.DeepEquals, resp.EncryptionPubKey[1].String())
		c.Assert(getResp.Address, qt.DeepEquals, signer.AddressString())
	})
}
