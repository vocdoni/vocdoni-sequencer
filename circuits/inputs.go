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
	votes []Vote[emulated.Element[sw_bn254.ScalarField]],
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
		inputs = append(inputs, v.Ballot.Serialize(api)...)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Address)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Commitment)
	}
	return inputs
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
