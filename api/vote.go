package api

import (
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// newVote creates a new voting process
// POST /vote
func (a *API) newVote(w http.ResponseWriter, r *http.Request) {
	// decode the vote
	vote := &Vote{}
	if err := json.NewDecoder(r.Body).Decode(vote); err != nil {
		ErrMalformedBody.Withf("could not decode request body: %v", err).Write(w)
		return
	}
	// get the encryption keys from db for the process id provided
	pid := new(types.ProcessID)
	if err := pid.Unmarshal(vote.ProcessID); err != nil {
		ErrMalformedBody.Withf("could not decode process id: %v", err).Write(w)
		return
	}
	// load the verification key for the ballot proof circuit, used by the user
	// to generate a proof of a valid ballot
	if err := ballotproof.Artifacts.LoadAll(); err != nil {
		ErrGenericInternalServerError.Withf("could not load artifacts: %v", err).Write(w)
		return
	}
	// convert the circom proof to gnark proof and verify it
	proof, err := circuits.VerifyAndConvertToRecursion(
		ballotproof.Artifacts.VerifyingKey(),
		vote.BallotProof,
		[]string{vote.BallotInputsHash.BigInt().String()},
	)
	if err != nil {
		ErrGenericInternalServerError.Withf("could not verify and convert proof: %v", err).Write(w)
		return
	}
	// push the ballot to the processor storage queue to be verified, aggregated
	// and published
	if err := a.storage.PushBallot(&storage.Ballot{
		ProcessID:        vote.ProcessID,
		VoterWeight:      new(big.Int).SetBytes(vote.CensusProof.Value),
		EncryptedBallot:  *vote.Ballot,
		Nullifier:        vote.Nullifier,
		Commitment:       vote.Commitment,
		Address:          vote.CensusProof.Key,
		BallotInputsHash: vote.BallotInputsHash,
		BallotProof:      *proof,
		Signature:        vote.Signature,
		CensusProof:      vote.CensusProof,
	}); err != nil {
		ErrGenericInternalServerError.Withf("could not push ballot: %v", err).Write(w)
		return
	}
	httpWriteOK(w)
}
