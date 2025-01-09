package voteverifier

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/config"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// Artifacts contains the circuit artifacts for the vote verifier circuit,
// which includes the proving and verification keys.
var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: config.VoteVerifierProvingKeyURL,
		Hash:      types.HexStringToHexBytes(config.VoteVerifierProvingKeyHash),
	},
	&circuits.Artifact{
		RemoteURL: config.VoteVerifierVerificationKeyURL,
		Hash:      types.HexStringToHexBytes(config.VoteVerifierVerificationKeyHash),
	},
)
