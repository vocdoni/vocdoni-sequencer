package aggregator

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/config"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// Artifacts contains the circuit artifacts for the aggregator circuit, which
// includes the proving and verification keys.
var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: config.AggregatorProvingKeyURL,
		Hash:      types.HexStringToHexBytes(config.AggregatorProvingKeyHash),
	},
	&circuits.Artifact{
		RemoteURL: config.AggregatorVerificationKeyURL,
		Hash:      types.HexStringToHexBytes(config.AggregatorVerificationKeyHash),
	},
)

// DummyArtifacts contains the circuit artifacts for the dummy circuit used
// to complete the number of expected recursive proofs where less than the
// expected number of proofs are received in a batch. It only contains the
// proving key because the verification key is fixed in the aggregator circuit.
var DummyArtifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: config.DummyProvingKeyURL,
		Hash:      types.HexStringToHexBytes(config.DummyProvingKeyHash),
	},
	nil,
)
