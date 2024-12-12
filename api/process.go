package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// newProcess creates a new voting process
// POST /process
func (a *API) newProcess(w http.ResponseWriter, r *http.Request) {
	p := &Process{}
	if err := json.NewDecoder(r.Body).Decode(p); err != nil {
		ErrMalformedBody.Withf("could not decode request body: %v", err).Write(w)
		return
	}

	// Extract the address from the signature
	address, err := ethereum.AddrFromSignature([]byte(fmt.Sprintf("%d%d", p.ChainID, p.Nonce)), p.Signature)
	if err != nil {
		ErrInvalidSignature.Withf("could not extract address from signature: %v", err).Write(w)
		return
	}

	// Create the process ID
	pid := types.ProcessID{
		Address: address,
		Nonce:   p.Nonce,
		ChainID: p.ChainID,
	}

	// Generate the elgamal key
	publicKey, privateKey, err := elgamal.GenerateKey(curves.New(curves.CurveTypeBN254))
	if err != nil {
		ErrGenericInternalServerError.Withf("could not generate elgamal key: %v", err).Write(w)
		return
	}
	x, y := publicKey.Point()

	// Create the process response
	pr := &ProcessResponse{
		ProcessID:        pid.Marshal(),
		EncryptionPubKey: [2]types.BigInt{types.BigInt(*x), types.BigInt(*y)},
		StateRoot:        types.HexBytes{}, // TO-DO
	}

	// Store the encryption keys
	if err := a.storage.StoreEncryptionKeys(pid, publicKey, privateKey); err != nil {
		ErrGenericInternalServerError.Withf("could not store encryption keys: %v", err).Write(w)
		return
	}

	// Write the response
	log.Infow("new process", "processId", pr.ProcessID.String(), "pubKey", pr.EncryptionPubKey, "stateRoot", pr.StateRoot.String())
	httpWriteJSON(w, pr)
}
