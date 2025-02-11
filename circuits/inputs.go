package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards"
)

// CircomInputs returns all values that are hashed to produce the public input
// needed to verify CircomProof, in a predefined order:
//
//	BallotMode
//	Address
//	UserWeight
//	ProcessID
//	EncryptionKey (in TE format)
//	Nullifier
//	Commitment
//	Ballot (in TE format)
func CircomInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
	userWeight emulated.Element[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, vote.Address, userWeight, process.ID)
	ekx, eky, err := twistededwards.FromEmulatedRTEtoTE(api,
		process.EncryptionKey.PubKey[0],
		process.EncryptionKey.PubKey[1],
	)
	if err != nil {
		FrontendError(api, "failed to convert encryption key to RTE", err)
	}
	inputs = append(inputs, ekx, eky)
	inputs = append(inputs, vote.Nullifier, vote.Commitment)
	for _, field := range vote.Ballot {
		c1x, c1y, err := twistededwards.FromEmulatedRTEtoTE(api, field.C1.X, field.C1.Y)
		if err != nil {
			FrontendError(api, "failed to convert encrypted field to RTE", err)
		}
		c2x, c2y, err := twistededwards.FromEmulatedRTEtoTE(api, field.C2.X, field.C2.Y)
		if err != nil {
			FrontendError(api, "failed to convert encrypted field to RTE", err)
		}
		inputs = append(inputs, c1x, c1y, c2x, c2y)
	}
	return inputs
}

// VoteVerifierInputs returns all values that are hashed to produce the public
// input needed to verify VoteVerifier, in a predefined order:
//
//	ProcessID
//	CensusRoot
//	EncryptionKey (in RTE format)
//	BallotMode
//	Nullifier
//	Ballot (in RTE format)
//	Address
//	Commitment
func VoteVerifierInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.ID, process.CensusRoot)
	inputs = append(inputs, process.EncryptionKey.Serialize()...)
	inputs = append(inputs, process.BallotMode.Serialize()...)
	inputs = append(inputs, vote.Address, vote.Nullifier, vote.Commitment)
	inputs = append(inputs, vote.Ballot.Serialize()...)
	return inputs
}

// AggregatorWitnessInputs returns all values that are hashed to produce the
// public input needed to verify AggregatorProof, in a predefined order:
//
//	ProcessID
//	CensusRoot
//	BallotMode
//	EncryptionKey (in RTE format)
//	Nullifiers
//	Ballots (in RTE format)
//	Addressess
//	Commitments
func AggregatorWitnessInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	votes []EmulatedVote[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.ID, process.CensusRoot)
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
	for i := 0; i < VotesPerBatch; i++ {
		votersHashes[i] = VoterHashFn(api, VoteVerifierInputs(api, process, votes[i])...)
	}
	return VotersHashes{votersHashes}
}

// AggregatorWitnessInputsAsVars returns all values that are hashed
// to produce the public input needed to verify AggregatorProof,
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
func AggregatorWitnessInputsAsVars(api frontend.API,
	process Process[frontend.Variable],
	votes []Vote[frontend.Variable],
) []frontend.Variable {
	// TODO: dedup AggregatorWitnessInputs and AggregatorWitnessInputsAsVars somehow
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
