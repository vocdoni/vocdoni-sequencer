package api

import (
	"bytes"
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
	// get the process from the storage
	pid := new(types.ProcessID)
	if err := pid.Unmarshal(vote.ProcessID); err != nil {
		ErrMalformedBody.Withf("could not decode process id: %v", err).Write(w)
		return
	}
	process, err := a.storage.Process(pid)
	if err != nil {
		ErrGenericInternalServerError.Withf("could not get process: %v", err).Write(w)
		return
	}
	// check that the census root is the same as the one in the process
	if !bytes.Equal(process.Census.CensusRoot, vote.CensusProof.Root) {
		ErrGenericInternalServerError.Withf("census root mismatch").Write(w)
		return
	}
	// TODO: verify the census proof

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
	// TODO: verify the signature of the vote

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
