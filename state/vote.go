package state

import (
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
)

// Vote describes a vote with homomorphic ballot
type Vote struct {
	nullifier     []byte
	elgamalBallot *elgamal.Ciphertext
	// address       []byte
	// commitment    big.Int
}

// AddVote adds a vote to the state
//   - if nullifier exists, it counts as vote overwrite
//
// TODO: use Tx to rollback in case of failure
func (o *State) AddVote(v Vote) error {
	if len(o.votes) >= VoteBatchSize {
		return fmt.Errorf("too many votes for this batch")
	}

	// if nullifier exists, it's a vote overwrite, need to count the overwritten vote
	// so it's later added to circuit.ResultsSub
	if _, _, err := o.tree.Get(v.nullifier); err == nil {
		o.overwriteSum.Add(o.overwriteSum, o.oldVote(v.nullifier))
		o.overwriteCount++
	}

	o.ballotSum.Add(o.ballotSum, v.elgamalBallot)
	o.ballotCount++

	o.votes = append(o.votes, v)

	o.storeVote(v.nullifier, v.elgamalBallot)
	return nil
}
