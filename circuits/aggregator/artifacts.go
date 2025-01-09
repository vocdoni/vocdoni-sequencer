package aggregator

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/config"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

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

var DummyArtifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: config.DummyProvingKeyURL,
		Hash:      types.HexStringToHexBytes(config.DummyProvingKeyHash),
	},
	nil,
)
