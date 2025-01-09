package voteverifier

import "github.com/vocdoni/vocdoni-z-sandbox/circuits"

var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/voteverifier/voteverifier.pk"},
	&circuits.Artifact{RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/voteverifier/voteverifier.vk"},
)
