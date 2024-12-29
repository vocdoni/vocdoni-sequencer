package ballotproof

import "github.com/vocdoni/vocdoni-z-sandbox/circuits"

const (
	// default process config
	NLevels         = circuits.CensusProofMaxLevels
	NFields         = circuits.BallotNumFields
	MaxCount        = 5
	ForceUniqueness = 0
	MaxValue        = 16
	MinValue        = 0
	CostExp         = 2
	CostFromWeight  = 0
	Weight          = 10
)

var Curve = circuits.BallotEncryptionCurve
