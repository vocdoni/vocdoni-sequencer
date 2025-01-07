package api

import (
	"encoding/json"
	"net/http"

	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// newVote creates a new voting process
// POST /vote
func (a *API) newVote(w http.ResponseWriter, r *http.Request) {
	// 1. decode the vote
	vote := &Vote{}
	if err := json.NewDecoder(r.Body).Decode(vote); err != nil {
		ErrMalformedBody.Withf("could not decode request body: %v", err).Write(w)
	}
	// get the encryption keys from db for the process id provided
	pid := new(types.ProcessID)
	if err := pid.Unmarshal(vote.ProcessID); err != nil {
		ErrMalformedBody.Withf("could not decode process id: %v", err).Write(w)
		return
	}
	encryptionKeys, _, err := a.storage.EncryptionKeys(*pid)
	if err != nil {
		ErrGenericInternalServerError.Withf("could not get encryption keys: %v", err).Write(w)
	}
	// get process metadata
	metadata, err := a.storage.ProcessMetadata(*pid)
	if err != nil {
		ErrGenericInternalServerError.Withf("could not get process metadata: %v", err).Write(w)
	}
	// convert the circom proof to gnark proof and verify it
	// TODO: get verification key from somewhere
	vkey := []byte{}
	proof, err := circuits.VerifyAndConvertToRecursion(vkey, &vote.VoteProof, vote.VotePubSignals)
	if err != nil {
		ErrGenericInternalServerError.Withf("could not verify and convert proof: %v", err).Write(w)
	}
}
