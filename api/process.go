package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
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

	// Store the encryption keys
	if err := a.storage.SetEncryptionKeys(pid, publicKey, privateKey); err != nil {
		ErrGenericInternalServerError.Withf("could not store encryption keys: %v", err).Write(w)
		return
	}

	// Initialize the state
	st, err := state.New(memdb.New(), pid.Marshal())
	if err != nil {
		ErrGenericInternalServerError.Withf("could not create state: %v", err).Write(w)
		return
	}
	defer st.Close()

	if err := st.Initialize(p.CensusRoot,
		circuits.BallotModeFromBM(p.BallotMode).Bytes(),
		circuits.EncryptionKeyFromECCPoint(publicKey).Bytes()); err != nil {
		ErrGenericInternalServerError.Withf("could not initialize state: %v", err).Write(w)
		return
	}
	root, err := st.RootAsBigInt()
	if err != nil {
		ErrGenericInternalServerError.Withf("could not get state root: %v", err).Write(w)
		return
	}

	// Create the process response
	pr := &ProcessResponse{
		ProcessID:        pid.Marshal(),
		EncryptionPubKey: [2]types.BigInt{types.BigInt(*x), types.BigInt(*y)},
		StateRoot:        root.Bytes(),
	}

	// Write the response
	log.Infow("new process",
		"processId", pr.ProcessID.String(),
		"pubKeyX", pr.EncryptionPubKey[0].String(),
		"pubKeyY", pr.EncryptionPubKey[1].String(),
		"stateRoot", pr.StateRoot.String(),
	)
	httpWriteJSON(w, pr)
}

// getProcess retrieves a voting process
// GET /process?id=<processId>
func (a *API) process(w http.ResponseWriter, r *http.Request) {
	// Unmarshal the process ID
	pidBytes, err := hex.DecodeString(r.URL.Query().Get("id"))
	if err != nil {
		ErrMalformedProcessID.Withf("could not decode process ID: %v", err).Write(w)
		return
	}
	pid := types.ProcessID{}
	if err := pid.Unmarshal(pidBytes); err != nil {
		ErrMalformedProcessID.Withf("could not unmarshal process ID: %v", err).Write(w)
		return
	}

	// Retrieve the process
	pubk, _, err := a.storage.EncryptionKeys(pid)
	if err != nil {
		ErrProcessNotFound.Withf("could not retrieve process: %v", err).Write(w)
		return
	}

	// Create the process response
	x, y := pubk.Point()
	pr := &ProcessResponse{
		ProcessID:        pid.Marshal(),
		Address:          pid.Address.Hex(),
		ChainID:          pid.ChainID,
		Nonce:            pid.Nonce,
		EncryptionPubKey: [2]types.BigInt{types.BigInt(*x), types.BigInt(*y)},
		StateRoot:        types.HexBytes{}, // TO-DO
	}

	// Write the response
	httpWriteJSON(w, pr)
}
