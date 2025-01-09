package aggregator

import "github.com/vocdoni/vocdoni-z-sandbox/circuits"

var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/aggregator.pk"},
	&circuits.Artifact{RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/aggregator.vk"},
)

var DummyArtifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/aggregator/dummy.pk"},
	nil,
)
