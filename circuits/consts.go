package circuits

import (
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

// curves
var (
	// BallotEncryptionCurve is the curve used for the encryption for ballots and results
	BallotEncryptionCurve = curves.New(curves.CurveTypeBabyJubJubGnark)
	// EncryptionKeysCurve is the curve used for generating the publicKey and privateKey of a new process
	EncryptionKeysCurve = curves.New(curves.CurveTypeBN254)
)

// hash funcs

var (
	// hash function used in the state tree
	StateTreeHashFunc = arbo.HashFunctionMiMC_BN254
	// hash function used in the census tree
	CensusProofHashFunc = arbo.HashFunctionMiMC_BLS12_377
)

// ballotproof
const (
	// default process config
	CensusProofMaxLevels = 160
	BallotNumFields      = 8
	MaxCount             = 5
	ForceUniqueness      = 0
	MaxValue             = 16
	MinValue             = 0
	CostExp              = 2
	CostFromWeight       = 0
	Weight               = 10
)

// voteverifier

// aggregator
const (
	// number of votes processed in each AggregatedProof
	VoteBatchSize = 10
)

// statetransition
const (
	// size of the merkle proofs
	StateTreeMaxLevels = 160
)
