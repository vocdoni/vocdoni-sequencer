package api

import (
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
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
	// convert the circom proof to gnark proof and verify it
	// TODO: get verification key from somewhere
	vkey := []byte{}
	proof, err := circuits.VerifyAndConvertToRecursion(vkey, &vote.BallotProof, []string{vote.BallotInputsHash.String()})
	if err != nil {
		ErrGenericInternalServerError.Withf("could not verify and convert proof: %v", err).Write(w)
	}
	// set the ballot info in the processor
	if err := a.storage.PushBallot(&storage.Ballot{
		ProcessID:        vote.ProcessID,
		VoterWeight:      new(big.Int).SetBytes(vote.CensusProof.Weight),
		EncryptedBallot:  vote.Cipherfields,
		Nullifier:        vote.Nullifier,
		Commitment:       vote.Commitment,
		Address:          vote.CensusProof.Address,
		BallotInputsHash: vote.BallotInputsHash,
		BallotProof:      *proof,
		Signature:        vote.Signature,
		CensusProof:      vote.CensusProof,
	}); err != nil {
		ErrGenericInternalServerError.Withf("could not push ballot: %v", err).Write(w)
	}
}
