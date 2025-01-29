package statetransitiontest

import (
	"fmt"
	"math"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
)

func ballotMode() circuits.BallotMode[frontend.Variable] {
	return circuits.BallotMode[frontend.Variable]{
		MaxCount:        ballottest.MaxCount,
		ForceUniqueness: ballottest.ForceUniqueness,
		MaxValue:        ballottest.MaxValue,
		MinValue:        ballottest.MinValue,
		MaxTotalCost:    int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount,
		MinTotalCost:    ballottest.MaxCount,
		CostExp:         ballottest.CostExp,
		CostFromWeight:  ballottest.CostFromWeight,
	}
}

func GenerateWitnesses(o *state.State) (*statetransition.Circuit, error) {
	var err error
	witness := &statetransition.Circuit{}

	// RootHashBefore
	witness.RootHashBefore, err = o.RootAsBigInt()
	if err != nil {
		return nil, err
	}

	// first get MerkleProofs, since they need to belong to RootHashBefore, i.e. before MerkleTransitions
	if witness.ProcessIDProof, err = statetransition.GenMerkleProof(o, state.KeyProcessID); err != nil {
		return nil, err
	}
	if witness.CensusRootProof, err = statetransition.GenMerkleProof(o, state.KeyCensusRoot); err != nil {
		return nil, err
	}
	if witness.BallotModeProof, err = statetransition.GenMerkleProof(o, state.KeyBallotMode); err != nil {
		return nil, err
	}
	if witness.EncryptionKeyProof, err = statetransition.GenMerkleProof(o, state.KeyEncryptionKey); err != nil {
		return nil, err
	}

	// now build ordered chain of MerkleTransitions

	// add Ballots
	for i := range witness.Ballot {
		if i < len(o.Votes()) {
			witness.Ballot[i], err = statetransition.MerkleTransitionFromAddOrUpdate(o,
				o.Votes()[i].Nullifier, o.Votes()[i].Ballot.Serialize())
		} else {
			witness.Ballot[i], err = statetransition.MerkleTransitionFromNoop(o)
		}
		if err != nil {
			return nil, err
		}
	}

	// add Commitments
	for i := range witness.Commitment {
		if i < len(o.Votes()) {
			witness.Commitment[i], err = statetransition.MerkleTransitionFromAddOrUpdate(o,
				o.Votes()[i].Address, arbo.BigIntToBytes(32, o.Votes()[i].Commitment))
		} else {
			witness.Commitment[i], err = statetransition.MerkleTransitionFromNoop(o)
		}
		if err != nil {
			return nil, err
		}
	}

	// update ResultsAdd
	witness.ResultsAdd, err = statetransition.MerkleTransitionFromAddOrUpdate(o,
		state.KeyResultsAdd, o.ResultsAdd.Add(o.ResultsAdd, o.BallotSum).Serialize())
	if err != nil {
		return nil, fmt.Errorf("ResultsAdd: %w", err)
	}

	// update ResultsSub
	witness.ResultsSub, err = statetransition.MerkleTransitionFromAddOrUpdate(o,
		state.KeyResultsSub, o.ResultsSub.Add(o.ResultsSub, o.OverwriteSum).Serialize())
	if err != nil {
		return nil, fmt.Errorf("ResultsSub: %w", err)
	}

	// update stats
	witness.NumNewVotes = o.BallotCount()
	witness.NumOverwrites = o.OverwriteCount()

	// RootHashAfter
	witness.RootHashAfter, err = o.RootAsBigInt()
	if err != nil {
		return nil, err
	}

	return witness, nil
}
