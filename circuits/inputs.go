package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// CircomInputs returns all values that are hashed to produce the public input
// needed to verify CircomProof, in a predefined order:
//
//	Process.ID
//	Process.BallotMode
//	Process.EncryptionKey (in Twisted Edwards format)
//	EmulatedVote.Address
//	EmulatedVote.Commitment
//	EmulatedVote.Nullifier
//	EmulatedVote.Ballot (in Twisted Edwards format)
//	userWeight
func CircomInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
	userWeight emulated.Element[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.SerializeForBallotProof(api)...)
	inputs = append(inputs, vote.SerializeForBallotProof(api)...)
	inputs = append(inputs, userWeight)

	return inputs
}

// VoteVerifierInputs returns all values that are hashed to produce the public
// input needed to verify VoteVerifier, in a predefined order:
//
//	Process.ID
//	Process.CensusRoot
//	Process.BallotMode (in RTE format)
//	Process.EncryptionKey
//	EmulatedVote.Address
//	EmulatedVote.Commitment
//	EmulatedVote.Nullifier
//	EmulatedVote.Ballot (in RTE format)
func VoteVerifierInputs(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	vote EmulatedVote[sw_bn254.ScalarField],
) []emulated.Element[sw_bn254.ScalarField] {
	inputs := []emulated.Element[sw_bn254.ScalarField]{}
	inputs = append(inputs, process.Serialize()...)
	inputs = append(inputs, vote.Serialize()...)
	return inputs
}

func CalculateVotersHashes(api frontend.API,
	process Process[emulated.Element[sw_bn254.ScalarField]],
	votes []EmulatedVote[sw_bn254.ScalarField],
) VotersHashes {
	// initialize the hashes of the voters
	votersHashes := [VotesPerBatch]emulated.Element[sw_bn254.ScalarField]{}
	for i := 0; i < VotesPerBatch; i++ {
		vinputs := VoteVerifierInputs(api, process, votes[i])
		votersHashes[i] = VoterHashFn(api, vinputs...)
	}
	return VotersHashes{votersHashes}
}
