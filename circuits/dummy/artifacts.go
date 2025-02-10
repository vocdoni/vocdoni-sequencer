package dummy

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/config"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// DummyArtifacts contains the circuit artifacts for the dummy circuit used
// to complete the number of expected recursive proofs where less than the
// expected number of proofs are received in a batch. It only contains the
// proving key because the verification key is fixed in the aggregator circuit.
var DummyArtifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: config.DummyCircuitURL,
		Hash:      types.HexStringToHexBytes(config.DummyCircuitHash),
	},
	&circuits.Artifact{
		RemoteURL: config.DummyProvingKeyURL,
		Hash:      types.HexStringToHexBytes(config.DummyProvingKeyHash),
	},
	&circuits.Artifact{
		RemoteURL: config.DummyVerificationKeyURL,
		Hash:      types.HexStringToHexBytes(config.DummyVerificationKeyHash),
	},
)
