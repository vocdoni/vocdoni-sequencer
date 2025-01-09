package aggregator

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/aggregator.pk",
		Hash:      types.HexStringToHexBytes("aecef25b7f5cd6c28df19d5398a7c9d6922149fdc60d7ebfee549eb42d84abe9"),
	},
	&circuits.Artifact{
		RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/aggregator.vk",
		Hash:      types.HexStringToHexBytes("c748f9e234d70c0123f116a5a88b81ad1bcf782a9d9d0d50d2caa196aac2c0fb"),
	},
)

var DummyArtifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/dummy.pk",
		Hash:      types.HexStringToHexBytes("fa587e9f24473de364d8950c70be11f6c33118b0be12df4ee100eed0dabecff2"),
	},
	nil,
)
