package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// CircomInputs returns all values that are hashed
// to produce the public input needed to verify CircomProof,
// in a predefined order:
//
//	BallotMode
//	Address
//	UserWeight
//	ProcessID
//	EncryptionKey
//	Nullifier
//	Commitment
//	Ballot
func CircomInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
	userWeight emulated.Element[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, vote.Address)
	inputs = append(inputs, userWeight)
	inputs = append(inputs, process.ID)
	inputs = append(inputs, process.EncryptionKey.Serialize()...)
	inputs = append(inputs, vote.Nullifier)
	inputs = append(inputs, vote.Commitment)
	inputs = append(inputs, vote.Ballot.Serialize()...)
	return inputs
}

// VoteVerifierInputs returns all values that are hashed
// to produce the public input needed to verify VoteVerifier,
// in a predefined order:
//
//	ProcessID
//	CensusRoot
//	BallotMode
//	EncryptionKey
//	Nullifier
//	Ballot
//	Address
//	Commitment
func VoteVerifierInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.ID)
	inputs = append(inputs, process.CensusRoot)
	inputs = append(inputs, process.EncryptionKey.Serialize()...)
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, vote.Address)
	inputs = append(inputs, vote.Nullifier)
	inputs = append(inputs, vote.Commitment)
	inputs = append(inputs, vote.Ballot.Serialize()...)
	return inputs
}

// AggregatedWitnessInputs returns all values that are hashed
// to produce the public input needed to verify AggregatedProof,
// in a predefined order:
//
//	ProcessID
//	CensusRoot
//	BallotMode
//	EncryptionKey
//	Nullifiers
//	Ballots
//	Addressess
//	Commitments
func AggregatedWitnessInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	votes []EmulatedVote[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.ID)
	inputs = append(inputs, process.CensusRoot)
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, process.EncryptionKey.Serialize()...)
	for _, v := range votes {
		inputs = append(inputs, v.Nullifier)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Ballot.Serialize()...)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Address)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Commitment)
	}
	return inputs
}

func CalculateVotersHashes(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	votes []EmulatedVote[sw_bn254.ScalarField],
) VotersHashes {
	// initialize the hashes of the voters
	votersHashes := [VotesPerBatch]emulated.Element[sw_bn254.ScalarField]{}
	// group common inputs
	commonInputs := process.Serialize()
	// iterate over the voters
	for i := 0; i < VotesPerBatch; i++ {
		// group remaining inputs, those that are unique for each voter
		voterInputs := append(commonInputs, votes[i].Serialize()...)
		// calculate the voter hash and store it
		votersHashes[i] = VoterHashFn(api, voterInputs...)
	}
	return VotersHashes{votersHashes}
}

// AggregatedWitnessInputsAsVars returns all values that are hashed
// to produce the public input needed to verify AggregatedProof,
// in a predefined order:
//
//	ProcessID
//	CensusRoot
//	BallotMode
//	EncryptionKey
//	Nullifiers
//	Ballots
//	Addressess
//	Commitments
func AggregatedWitnessInputsAsVars(api frontend.API,
	process Process[frontend.Variable],
	votes []Vote[frontend.Variable],
) []frontend.Variable {
	// TODO: dedup AggregatedWitnessInputs and AggregatedWitnessInputsAsVars somehow
	inputs := []frontend.Variable{}
	inputs = append(inputs, process.ID)
	inputs = append(inputs, process.CensusRoot)
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, process.EncryptionKey.Serialize()...)
	for _, v := range votes {
		inputs = append(inputs, v.Nullifier)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Ballot.SerializeVars()...)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Address)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Commitment)
	}
	return inputs
}
